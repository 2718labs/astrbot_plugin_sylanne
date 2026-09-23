"""Internal B2.2 prepared-dispatch journal/Authority transaction bridge.

The host service supplies an authenticated subject; Core's authorizer and D08
verifier run before locks. A handoff start is a durable boundary, not a platform
send or a production RuntimeDependency.
The `prepared`, `claimed` and verified `observed` phases are service-owned
journal transitions. Observation preserves the platform's stated evidence
scope; `handed_off` and `unknown` do not prove delivery or settlement.
The persistent v2-only Core seal
gates legacy entrances; deletion and execution writers are frozen in a fixed
order before each append or final Authority commit.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json

from ..runtime_journal import RecoveryConstraintFootprint
from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .local_bridge import constraint_keys_from_footprint
from .v2_contract import (
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    PendingMutationV2, canonical_bytes,
    canonical_digest,
    PlatformObservationV1, decode_bytes, from_wire, to_wire,
)
from .v2_execution_journal import AuthorityV2ExecutionJournal, VerifiedAppendV2
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_fence_store import AuthorityV2FenceStore


_HANDOFF_DDL = """CREATE TABLE authority_execution_handoff_starts_v1 (
                handoff_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL UNIQUE,
                namespace TEXT NOT NULL,
                subject TEXT NOT NULL,
                claim_digest TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                graph_claim_ref TEXT NOT NULL,
                permit BLOB NOT NULL
            ) STRICT"""


@dataclass(frozen=True, slots=True)
class PreparedExecutionObservationV2:
    """Verified local prepare state; no platform outcome is represented."""

    append: VerifiedAppendV2 | None
    result: tuple[MutationReceiptV2, FencePermitV2] | None


@dataclass(frozen=True, slots=True)
class HandoffStartV2:
    """One durable Authority start bound to a current dispatch fence.

    The business graph's independently durable claim is named, not reproduced.
    This receipt alone cannot authorize a platform adapter to send.
    """

    handoff_id: str
    operation_id: str
    effect_id: str
    namespace: str
    claim_digest: str
    binding_digest: str
    graph_claim_ref: str
    permit: FencePermitV2
    replay: bool = False

    def __post_init__(self) -> None:
        for name in ("handoff_id", "operation_id", "effect_id", "namespace",
                     "graph_claim_ref"):
            identifier(getattr(self, name), name)
        if type(self.replay) is not bool:
            raise ValueError("handoff replay must be an exact boolean")
        if (type(self.permit) is not FencePermitV2
                or self.permit.operation != "dispatch"
                or self.permit.operation_id != self.operation_id
                or self.permit.effect_id != self.effect_id
                or self.permit.namespace != self.namespace
                or any(type(value) is not str or not value.startswith("sha256:")
                       or len(value) != 71
                       or any(ch not in "0123456789abcdef" for ch in value[7:])
                       for value in (
                           self.claim_digest, self.binding_digest))):
            raise ValueError("handoff start identity is invalid")

    def to_wire(self) -> dict[str, object]:
        return {"handoff_id": self.handoff_id, "operation_id": self.operation_id,
                "effect_id": self.effect_id, "namespace": self.namespace,
                "claim_digest": self.claim_digest,
                "binding_digest": self.binding_digest,
                "graph_claim_ref": self.graph_claim_ref,
                "permit": to_wire(self.permit), "replay": self.replay}

    @classmethod
    def from_wire(cls, value: object) -> "HandoffStartV2":
        if type(value) is not dict or set(value) != {
                "handoff_id", "operation_id", "effect_id", "namespace",
                "claim_digest", "binding_digest", "graph_claim_ref", "permit",
                "replay"}:
            raise ValueError("handoff start wire fields differ")
        permit = from_wire(value["permit"])
        result = cls(**{key: item for key, item in value.items() if key != "permit"},
                     permit=permit)
        if result.to_wire() != value:
            raise ValueError("handoff start wire is not canonical")
        return result


class AuthorityV2ExecutionBridge:
    """One isolated service namespace using Core's real Authority DB and lock."""

    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceStore,
                 journal: AuthorityV2ExecutionJournal, namespace: str,
                 deletion: AuthorityV2DeletionGuard | None = None,
                 observation_verifier=None, final_handoff_authorizer=None):
        identifier(namespace, "namespace")
        if (type(core) is not AuthorityServiceCore
                or type(fences) is not AuthorityV2FenceStore
                or type(journal) is not AuthorityV2ExecutionJournal
                or core._db is not fences._db or core._lock is not fences._lock
                or journal.namespace != namespace):
            raise AuthorityUnavailable("v2 bridge requires one service Authority DB/lock and namespace")
        self.core = core
        self.fences = fences
        self.journal = journal
        self.namespace = namespace
        with core._tx() as db:
            self._require_v2_mode_locked(db)
        if type(deletion) is not AuthorityV2DeletionGuard:
            raise AuthorityUnavailable("v2 execution requires deletion writer guard")
        self.deletion = deletion
        if observation_verifier is not None and not callable(observation_verifier):
            raise AuthorityUnavailable("platform observation verifier must be installed by service")
        self._observation_verifier = observation_verifier
        if final_handoff_authorizer is not None and not callable(final_handoff_authorizer):
            raise AuthorityUnavailable("final handoff authorizer must be installed by service")
        # Contract: callback atomically checks current business-graph RequiredChecks
        # and reserves a durable, replayable graph claim keyed by handoff_id. It
        # runs outside Core and both journal locks; it must never call back into
        # this Authority bridge. Missing callback keeps handoff closed.
        self._final_handoff_authorizer = final_handoff_authorizer
        with core._tx() as db:
            stored = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' "
                "AND name='authority_execution_handoff_starts_v1'").fetchone()
            if stored is None:
                db.execute(_HANDOFF_DDL)
            elif stored != (_HANDOFF_DDL,):
                raise AuthorityUnavailable("handoff start schema differs")

    def _check_deletion_locked(self, db, head):
        row = self.core._row(db, self.namespace)
        if row[6:9] != (head.journal_id, head.seq, head.digest) or row[9] != "clear":
            raise AuthorityUnavailable("deletion journal changed or is not settled")

    def _check_execution_head_locked(self, db, head):
        row = self.core._row(db, self.namespace)
        if row[10:13] != (head.journal_id, head.seq, head.digest):
            raise AuthorityUnavailable("execution journal differs from Authority head")

    @staticmethod
    def _require_v2_mode_locked(db) -> None:
        mode = db.execute(
            "SELECT value FROM authority_meta WHERE key='service_mode'").fetchone()
        if mode != ("v2-only",):
            raise AuthorityUnavailable("v2 execution requires persistent v2-only service mode")
        AuthorityServiceCore._require_no_deletion_migration(db)

    @staticmethod
    def _request_digest(permit: FencePermitV2, mutation_id: str,
                        footprint: RecoveryConstraintFootprint) -> str:
        material = json.dumps({
            "permit": to_wire(permit), "mutation_id": mutation_id,
            "footprint": json.loads(footprint._json()), "phase": "prepared",
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return "sha256:" + hashlib.sha256(material).hexdigest()

    def _build_pending(self, permit: FencePermitV2, mutation_id: str,
                       footprint: RecoveryConstraintFootprint) -> PendingMutationV2:
        request_digest = self._request_digest(permit, mutation_id, footprint)
        append_id = "append-" + hashlib.sha256(
            (mutation_id + "\0" + request_digest).encode()).hexdigest()
        draft = PendingMutationV2(
            permit=permit, mutation_id=mutation_id, request_digest=request_digest,
            phase="prepared", before_anchor=permit.pinned_anchor,
            expected_append_id=append_id,
            expected_append_digest="sha256:" + "0" * 64,
        )
        return replace(draft, expected_append_digest=
                       self.journal.expected_digest(draft))

    def _build_claim_pending(self, receipt: MutationReceiptV2,
                             binding: ExecutionBindingV1 | ExecutionBindingV2) -> PendingMutationV2:
        if (type(receipt) is not MutationReceiptV2
                or receipt.pending.phase != "prepared"
                or receipt.durable_state != "committed"
                or type(binding) not in (ExecutionBindingV1, ExecutionBindingV2)
                or binding.permit != receipt.pending.permit):
            raise AuthorityUnavailable("claim requires the original committed prepare")
        permit = replace(receipt.pending.permit,
                         revision=receipt.updated_revision,
                         pinned_anchor=receipt.after_anchor)
        mutation_id = "claim-" + hashlib.sha256((
            permit.operation_id + "\0" + receipt.pending.mutation_id).encode()).hexdigest()
        # FenceStore schema 4 computes this request digest over the permit and
        # original footprint. The claimed phase and binding are in the canonical
        # pending bytes and execution chain digest, and are checked on replay.
        request_digest = self._request_digest(permit, mutation_id, binding.footprint)
        append_id = "append-" + hashlib.sha256((
            mutation_id + "\0" + request_digest).encode()).hexdigest()
        draft = PendingMutationV2(
            permit=permit, mutation_id=mutation_id,
            request_digest=request_digest, phase="claimed",
            before_anchor=permit.pinned_anchor,
            expected_append_id=append_id,
            expected_append_digest="sha256:" + "0" * 64,
            prepared_receipt=receipt, binding=binding)
        return replace(draft, expected_append_digest=
                       self.journal.expected_digest(draft))

    def _build_observed_pending(self, receipt: MutationReceiptV2,
                                observation: PlatformObservationV1,
                                predecessor: MutationReceiptV2) -> PendingMutationV2:
        if (type(receipt) is not MutationReceiptV2
                or receipt.pending.phase != "claimed"
                or receipt.durable_state != "committed"
                or type(observation) is not PlatformObservationV1
                or observation.binding != receipt.pending.binding
                or type(predecessor) is not MutationReceiptV2
                or predecessor.durable_state != "committed"
                or predecessor.pending.phase not in ("claimed", "observed")
                or (predecessor.pending.phase == "observed"
                    and predecessor.pending.claimed_receipt != receipt)):
            raise AuthorityUnavailable("observation requires the original committed claim")
        permit = replace(predecessor.pending.permit,
                         revision=predecessor.updated_revision,
                         pinned_anchor=predecessor.after_anchor)
        mutation_id = "observe-" + hashlib.sha256((
            permit.operation_id + "\0" + observation.observation_id).encode()).hexdigest()
        request_digest = self._request_digest(
            permit, mutation_id, observation.binding.footprint)
        append_id = "append-" + hashlib.sha256((
            mutation_id + "\0" + request_digest).encode()).hexdigest()
        draft = PendingMutationV2(
            permit=permit, mutation_id=mutation_id,
            request_digest=request_digest, phase="observed",
            before_anchor=permit.pinned_anchor,
            expected_append_id=append_id,
            expected_append_digest="sha256:" + "0" * 64,
            claimed_receipt=receipt, platform_observation=observation,
            predecessor_mutation_id=predecessor.pending.mutation_id,
            predecessor_receipt_digest=canonical_digest(predecessor))
        return replace(draft, expected_append_digest=
                       self.journal.expected_digest(draft))

    def _check_core_owner(self, db, permit: FencePermitV2):
        core = self.core
        row = core._row(db, self.namespace)
        if (core._anchor(db, self.namespace, row) != permit.pinned_anchor
                or row[0] != permit.holder or row[1] != permit.generation
                or row[2] != "active" or row[9] != "clear"
                or core._id(db) != permit.authority_id
                or row[10] != self.journal.journal_id):
            raise AuthorityUnavailable("current namespace, holder or anchor differs from fence")
        return row

    def _check_fence_locked(self, db, permit: FencePermitV2, subject: str,
                            *, pending: PendingMutationV2 | None = None) -> None:
        row = self.fences._row(db, permit.operation_id)
        if (row is None or row[6] != "active" or self.fences._permit(row) != permit
                or permit.subject != subject or permit.namespace != self.namespace
                or row[10] != (canonical_bytes(pending) if pending else None)):
            raise AuthorityUnavailable("active v2 fence owner/revision/pending differs")

    @staticmethod
    def _check_effects(db, namespace: str, effect_id: str,
                       keys: tuple[str, ...]) -> None:
        if db.execute("SELECT 1 FROM authority_effects WHERE namespace=? AND effect_id=?",
                      (namespace, effect_id)).fetchone():
            raise AuthorityUnavailable("effect already has execution history")
        for state, encoded in db.execute(
                "SELECT state,conflict_keys_json FROM authority_effects WHERE namespace=?",
                (namespace,)):
            if state == "unresolved":
                old = set(json.loads(encoded))
                if not old or not keys or old.intersection(keys):
                    raise AuthorityUnavailable("unresolved effect constraint blocks dispatch")

    def _load_mutation_locked(self, db, pending: PendingMutationV2,
                              subject: str):
        row = self.fences.mutation_locked(db, pending.mutation_id)
        if row is None:
            raise AuthorityUnavailable("mutation ID is absent")
        if row[:4] != (pending.permit.operation_id, self.namespace, subject,
                       pending.request_digest) or row[6] != canonical_bytes(pending):
            raise AuthorityUnavailable("mutation ID identity or digest conflict")
        kind, saved, _, _ = self.fences._decode_mutation_row(row)
        if kind != "execution" or saved != pending:
            raise AuthorityUnavailable("mutation recovery footprint is absent or differs")
        return row

    @staticmethod
    def _completed_result(row):
        if row[4] == "pending":
            return None
        try:
            receipt = decode_bytes(row[7])
            permit = decode_bytes(row[8])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("malformed persisted mutation result") from exc
        if (type(receipt) is not MutationReceiptV2
                or type(permit) is not FencePermitV2
                or receipt.durable_state != row[4]
                or receipt.pending != decode_bytes(row[6])
                or permit.pinned_anchor != receipt.after_anchor
                or permit.revision != receipt.updated_revision):
            raise AuthorityUnavailable("persisted mutation result is inconsistent")
        return receipt, permit

    def _check_observed_source_locked(self, db, pending: PendingMutationV2,
                                      subject: str):
        claimed = pending.claimed_receipt
        claim_row = self._load_mutation_locked(db, claimed.pending, subject)
        claim_permit = replace(claimed.pending.permit,
                               revision=claimed.updated_revision,
                               pinned_anchor=claimed.after_anchor)
        if self._completed_result(claim_row) != (claimed, claim_permit):
            raise AuthorityUnavailable("original claimed receipt differs")
        prepared = claimed.pending.prepared_receipt
        prepare_row = self._load_mutation_locked(db, prepared.pending, subject)
        if self._completed_result(prepare_row) != (prepared, claimed.pending.permit):
            raise AuthorityUnavailable("original prepared receipt differs")
        footprint = self.fences._decode_footprint(prepared.pending, prepare_row[11])
        if (footprint != pending.platform_observation.binding.footprint
                or self.fences._decode_footprint(claimed.pending, claim_row[11])
                != footprint):
            raise AuthorityUnavailable("observation lost original recovery footprint")
        predecessor_id = pending.predecessor_mutation_id
        predecessor_row = self.fences.mutation_locked(db, predecessor_id)
        if predecessor_row is None:
            raise AuthorityUnavailable("observation predecessor is absent")
        kind, saved, predecessor, updated = self.fences._decode_mutation_row(
            predecessor_row)
        if (kind != "execution" or predecessor is None
                or predecessor_row[0:3] != (
                    pending.permit.operation_id, self.namespace, subject)
                or predecessor_row[4] != "committed"
                or predecessor.pending.mutation_id != predecessor_id
                or canonical_digest(predecessor) != pending.predecessor_receipt_digest
                or updated != pending.permit
                or predecessor.after_anchor != pending.before_anchor
                or predecessor.pending.permit.effect_id != pending.permit.effect_id
                or (predecessor_id == claimed.pending.mutation_id
                    and predecessor != claimed)
                or (predecessor_id != claimed.pending.mutation_id
                    and (saved.phase != "observed"
                         or saved.claimed_receipt != claimed))):
            raise AuthorityUnavailable("observation predecessor receipt or fence differs")
        if (self.fences._decode_footprint(saved, predecessor_row[11])
                != footprint):
            raise AuthorityUnavailable("observation predecessor footprint differs")
        return predecessor, footprint, predecessor_row

    def prepare_pending(self, *, credential, subject: str,
                        permit: FencePermitV2, mutation_id: str,
                        footprint: RecoveryConstraintFootprint) -> PendingMutationV2:
        """Durably mark pending before any execution journal write lock."""
        identifier(subject, "subject")
        identifier(mutation_id, "mutation_id")
        if (type(permit) is not FencePermitV2 or permit.operation != "dispatch"
                or permit.subject != subject or permit.namespace != self.namespace
                or type(footprint) is not RecoveryConstraintFootprint
                or footprint.namespace != self.namespace
                or footprint.effect_id != permit.effect_id):
            raise AuthorityUnavailable("dispatch fence or footprint identity mismatch")
        footprint_digest = "sha256:" + hashlib.sha256(
            footprint._json().encode()).hexdigest()
        if permit.footprint_digest != footprint_digest:
            raise AuthorityUnavailable("verified footprint digest differs from permit")
        keys = constraint_keys_from_footprint(footprint)
        core = self.core
        core._require(credential, "dispatch", self.namespace, permit.holder)
        try:
            verified = core._dispatch_verifier(self.namespace, permit.effect_id, keys)
        except Exception as exc:
            raise AuthorityUnavailable("D08 dispatch verification failed") from exc
        if verified is not True:
            raise AuthorityUnavailable("D08 dispatch verification denied")
        pending = self._build_pending(permit, mutation_id, footprint)
        # Journal observation ends before the Authority write transaction starts.
        head = self.journal.verified_head()
        if (head.journal_id, head.seq, head.digest) != (
                pending.before_anchor.execution_journal_id,
                pending.before_anchor.execution_seq,
                pending.before_anchor.execution_digest):
            raise AuthorityUnavailable("journal before-head differs from Authority fence")
        with core._tx() as db:
            self._require_v2_mode_locked(db)
            self.fences._check_schema(db)
            mutation = self.fences.mutation_locked(db, mutation_id)
            if mutation is not None:
                self._load_mutation_locked(db, pending, subject)
                return pending
            self._check_core_owner(db, permit)
            self._check_fence_locked(db, permit, subject)
            if db.execute("SELECT 1 FROM authority_permits WHERE namespace=? LIMIT 1",
                          (self.namespace,)).fetchone():
                raise AuthorityUnavailable("legacy permit overlaps v2 prepared dispatch")
            self._check_effects(db, self.namespace, permit.effect_id, keys)
            self.fences.record_pending_locked(
                db, pending, subject=subject,
                current_anchor=permit.pinned_anchor, footprint=footprint,
                conflict_keys=keys)
        return pending

    def prepare_claim_pending(self, *, credential, subject: str,
                              prepared_receipt: MutationReceiptV2,
                              binding: ExecutionBindingV1 | ExecutionBindingV2) -> PendingMutationV2:
        """Persist the claim intent for the same operation before its append."""
        identifier(subject, "subject")
        pending = self._build_claim_pending(prepared_receipt, binding)
        permit = pending.permit
        if permit.subject != subject or permit.namespace != self.namespace:
            raise AuthorityUnavailable("claim subject or namespace differs")
        self.core._require(credential, "execution", self.namespace, permit.holder)
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks claim")
                inspection = self.journal.inspect_expected(prepared_receipt.pending)
                if inspection.first_append is None:
                    raise AuthorityUnavailable("original prepared append is absent")
                with self.core._tx() as db:
                    self._require_v2_mode_locked(db)
                    self.fences._check_schema(db)
                    self._check_deletion_locked(db, deletion_head)
                    original = self._load_mutation_locked(
                        db, prepared_receipt.pending, subject)
                    if (self._completed_result(original) !=
                            (prepared_receipt, permit)):
                        raise AuthorityUnavailable("original prepared receipt differs")
                    footprint = self.fences._decode_footprint(
                        prepared_receipt.pending, original[11])
                    if footprint != binding.footprint:
                        raise AuthorityUnavailable("claim footprint differs from prepare")
                    existing = self.fences.mutation_locked(db, pending.mutation_id)
                    if existing is not None:
                        saved = self._load_mutation_locked(db, pending, subject)
                        if self._completed_result(saved) is not None:
                            self._check_execution_head_locked(db, inspection.verified_head)
                        return pending
                    if inspection.following_count != 1:
                        raise AuthorityUnavailable("prepared append is no longer current")
                    self._check_core_owner(db, permit)
                    self._check_fence_locked(db, permit, subject)
                    effect = db.execute(
                        "SELECT state,conflict_keys_json,execution_seq FROM authority_effects "
                        "WHERE namespace=? AND effect_id=?",
                        (self.namespace, permit.effect_id)).fetchone()
                    if effect != ("unresolved", original[5],
                                  prepared_receipt.pending.expected_execution_seq):
                        raise AuthorityUnavailable("prepared effect constraint differs")
                    self.fences.record_pending_locked(
                        db, pending, subject=subject,
                        current_anchor=permit.pinned_anchor, footprint=footprint,
                        conflict_keys=tuple(json.loads(original[5])))
        return pending

    def _existing_observation_locked(self, db, mutation_id: str,
                                     original_permit: FencePermitV2,
                                     claimed_receipt: MutationReceiptV2,
                                     observation: PlatformObservationV1,
                                     subject: str):
        existing = self.fences.mutation_locked(db, mutation_id)
        if existing is None:
            return None
        kind, pending, receipt, _ = self.fences._decode_mutation_row(existing)
        if (kind != "execution" or pending.phase != "observed"
                or existing[0:3] != (
                    original_permit.operation_id, self.namespace, subject)
                or pending.claimed_receipt != claimed_receipt
                or pending.platform_observation != observation):
            raise AuthorityUnavailable("observation ID reused with different evidence")
        self._check_observed_source_locked(db, pending, subject)
        observed = self.journal.inspect_expected(pending)
        if receipt is not None:
            if observed.first_append is None:
                raise AuthorityUnavailable("committed observation append is absent")
            self._check_execution_head_locked(db, observed.verified_head)
            return pending, True
        if observed.following_count > 1:
            raise AuthorityUnavailable("extra execution append quarantines observation")
        if observed.first_append is None:
            self._check_execution_head_locked(db, observed.verified_head)
        return pending, False

    def prepare_observation_pending(self, *, credential, subject: str,
                                    claimed_receipt: MutationReceiptV2,
                                    observation: PlatformObservationV1) -> PendingMutationV2:
        """Persist one verifier-qualified report after the current operation tail."""
        identifier(subject, "subject")
        if (type(claimed_receipt) is not MutationReceiptV2
                or claimed_receipt.pending.phase != "claimed"
                or claimed_receipt.durable_state != "committed"
                or type(observation) is not PlatformObservationV1
                or observation.binding != claimed_receipt.pending.binding):
            raise AuthorityUnavailable("observation requires the original committed claim")
        original_permit = claimed_receipt.pending.permit
        if original_permit.subject != subject or original_permit.namespace != self.namespace:
            raise AuthorityUnavailable("observation subject or namespace differs")
        self.core._require(credential, "execution", self.namespace,
                           original_permit.holder)
        mutation_id = "observe-" + hashlib.sha256((
            original_permit.operation_id + "\0" + observation.observation_id
        ).encode()).hexdigest()
        # A committed report is immutable evidence. Replaying it needs the
        # durable Authority and journal checks, not a live platform verifier.
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks observation")
                inspection = self.journal.inspect_expected(claimed_receipt.pending)
                if inspection.first_append is None:
                    raise AuthorityUnavailable("original claimed append is absent")
                with self.core._tx() as db:
                    self._require_v2_mode_locked(db)
                    self.fences._check_schema(db)
                    self._check_deletion_locked(db, deletion_head)
                    existing = self._existing_observation_locked(
                        db, mutation_id, original_permit, claimed_receipt,
                        observation, subject)
                    if existing is not None and existing[1]:
                        return existing[0]
                    if existing is None:
                        self._check_execution_head_locked(db, inspection.verified_head)
        verifier = self._observation_verifier
        if verifier is None:
            raise AuthorityUnavailable("service has no installed platform observation verifier")
        try:
            verified = verifier(self.namespace, claimed_receipt, observation)
        except Exception as exc:
            raise AuthorityUnavailable("platform observation verification failed") from exc
        if type(verified) is not PlatformObservationV1 or verified != observation:
            raise AuthorityUnavailable("platform observation evidence was not verified")
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks observation")
                inspection = self.journal.inspect_expected(claimed_receipt.pending)
                if inspection.first_append is None:
                    raise AuthorityUnavailable("original claimed append is absent")
                with self.core._tx() as db:
                    self._require_v2_mode_locked(db)
                    self.fences._check_schema(db)
                    self._check_deletion_locked(db, deletion_head)
                    existing = self._existing_observation_locked(
                        db, mutation_id, original_permit, claimed_receipt,
                        observation, subject)
                    if existing is not None:
                        return existing[0]
                    self._check_execution_head_locked(db, inspection.verified_head)
                    claim_row = self._load_mutation_locked(
                        db, claimed_receipt.pending, subject)
                    claim_permit = replace(claimed_receipt.pending.permit,
                                           revision=claimed_receipt.updated_revision,
                                           pinned_anchor=claimed_receipt.after_anchor)
                    if self._completed_result(claim_row) != (
                            claimed_receipt, claim_permit):
                        raise AuthorityUnavailable("original claimed receipt differs")
                    current_anchor = self.core._anchor(
                        db, self.namespace, self.core._row(db, self.namespace))
                    predecessor = claimed_receipt if current_anchor == claimed_receipt.after_anchor else None
                    predecessor_row = claim_row if predecessor is not None else None
                    if predecessor is None:
                        for row in db.execute(
                                "SELECT mutation_id FROM authority_v2_mutations "
                                "WHERE operation_id=? AND mutation_kind='execution' "
                                "AND state='committed'",
                                (original_permit.operation_id,)):
                            candidate_row = self.fences.mutation_locked(db, row[0])
                            kind, saved, receipt, _ = self.fences._decode_mutation_row(
                                candidate_row)
                            if (kind == "execution" and saved.phase == "observed"
                                    and receipt.after_anchor == current_anchor):
                                if predecessor is not None:
                                    raise AuthorityUnavailable("multiple current observation predecessors")
                                predecessor, predecessor_row = receipt, candidate_row
                    if predecessor is None:
                        raise AuthorityUnavailable("current operation has no committed observation tail")
                    pending = self._build_observed_pending(
                        claimed_receipt, observation, predecessor)
                    permit = pending.permit
                    _, footprint, _ = self._check_observed_source_locked(
                        db, pending, subject)
                    self._check_core_owner(db, permit)
                    self._check_fence_locked(db, permit, subject)
                    effect = db.execute(
                        "SELECT state,conflict_keys_json,execution_seq FROM authority_effects "
                        "WHERE namespace=? AND effect_id=?",
                        (self.namespace, permit.effect_id)).fetchone()
                    if effect != ("unresolved", predecessor_row[5],
                                  predecessor.pending.expected_execution_seq):
                        raise AuthorityUnavailable("observation effect constraint differs")
                    self.fences.record_pending_locked(
                        db, pending, subject=subject,
                        current_anchor=permit.pinned_anchor, footprint=footprint,
                        conflict_keys=tuple(json.loads(predecessor_row[5])))
        return pending

    def append_pending(self, pending: PendingMutationV2, *, credential,
                       subject: str):
        """Recheck durable pending under the sole writer, then sync one append."""
        if type(pending) is not PendingMutationV2 or pending.phase not in ("prepared", "claimed", "observed"):
            raise AuthorityUnavailable("unsupported dispatch append phase")
        identifier(subject, "subject")
        self.core._require(credential, "execution", self.namespace,
                           pending.permit.holder)
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks dispatch append")
                with self.core._tx() as db:
                    self._require_v2_mode_locked(db)
                    self.fences._check_schema(db)
                    self._check_deletion_locked(db, deletion_head)
                    self._check_core_owner(db, pending.permit)
                    self._check_fence_locked(db, pending.permit, subject,
                                             pending=pending)
                    mutation = self._load_mutation_locked(db, pending, subject)
                    if mutation[4] != "pending" or mutation[5] == "null":
                        raise AuthorityUnavailable("verified pending mutation is absent")
                return self.journal.append_once_guarded(pending)

    def reconcile_mutation(self, *, credential, subject: str,
                           pending: PendingMutationV2,
                           allow_cancel: bool = False):
        """Exactly 0 or 1 matching append; no replay of an external effect."""
        if type(pending) is not PendingMutationV2 or pending.phase not in ("prepared", "claimed", "observed"):
            raise AuthorityUnavailable("unsupported dispatch recovery phase")
        identifier(subject, "subject")
        self.core._require(credential, "recover" if allow_cancel else "execution",
                           self.namespace,
                           pending.permit.holder)
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
              deletion_head = self.deletion.verified_head()
              if self.deletion.has_deletion_history(self.namespace):
                  raise AuthorityUnavailable("historical deletion closure blocks dispatch recovery")
              inspection = None
              inspection_error = None
              verified_head = None
              try:
                  inspection = self.journal.inspect_expected(pending)
                  verified_head = inspection.verified_head
              except AuthorityUnavailable as exc:
                  # Completed idempotent retries can outlive later appends.
                  # Still require an independently verified full chain.
                  verified_head = self.journal.verified_head()
                  inspection_error = exc
              with self.core._tx() as db:
                self._require_v2_mode_locked(db)
                self.fences._check_schema(db)
                self._check_deletion_locked(db, deletion_head)
                mutation = self._load_mutation_locked(db, pending, subject)
                if pending.phase == "claimed":
                    original = self._load_mutation_locked(
                        db, pending.prepared_receipt.pending, subject)
                    if (self._completed_result(original) !=
                            (pending.prepared_receipt, pending.permit)
                            or self.fences._decode_footprint(
                                pending.prepared_receipt.pending, original[11])
                            != pending.binding.footprint):
                        raise AuthorityUnavailable("claim lost original prepared receipt or footprint")
                elif pending.phase == "observed":
                    self._check_observed_source_locked(db, pending, subject)
                completed = self._completed_result(mutation)
                if completed is not None:
                    if inspection_error is not None and pending.phase != "prepared":
                        raise inspection_error
                    self._check_execution_head_locked(db, verified_head)
                    return completed
                if inspection_error is not None:
                    raise inspection_error
                if inspection.following_count > 1:
                    raise AuthorityUnavailable("extra execution append quarantines pending fence")
                if inspection.following_count == 0 and pending.phase != "prepared":
                    raise AuthorityUnavailable(
                        f"{pending.phase} pending requires its original append")
                if inspection.following_count == 0 and not allow_cancel:
                    raise AuthorityUnavailable("prepared mutation has no durable append")
                self._check_core_owner(db, pending.permit)
                self._check_fence_locked(db, pending.permit, subject,
                                         pending=pending)
                if mutation[5] == "null":
                    raise AuthorityUnavailable("verified conflict keys are absent")
                keys = tuple(json.loads(mutation[5]))
                if inspection.following_count == 1:
                    if pending.phase == "prepared":
                        self._check_effects(db, self.namespace,
                                            pending.permit.effect_id, keys)
                        db.execute("INSERT INTO authority_effects(namespace,effect_id,state,conflict_keys_json,execution_seq) VALUES(?,?,?,?,?)", (
                            self.namespace, pending.permit.effect_id, "unresolved",
                            json.dumps(keys, separators=(",", ":")),
                            pending.expected_execution_seq))
                    elif pending.phase == "claimed":
                        original = self._load_mutation_locked(
                            db, pending.prepared_receipt.pending, subject)
                        if (self._completed_result(original) !=
                                (pending.prepared_receipt, pending.permit)
                                or self.fences._decode_footprint(
                                    pending.prepared_receipt.pending, original[11])
                                != pending.binding.footprint):
                            raise AuthorityUnavailable("original prepare changed before claim commit")
                        effect = db.execute(
                            "SELECT state,conflict_keys_json,execution_seq FROM authority_effects "
                            "WHERE namespace=? AND effect_id=?",
                            (self.namespace, pending.permit.effect_id)).fetchone()
                        if effect != ("unresolved", mutation[5],
                                      pending.prepared_receipt.pending.expected_execution_seq):
                            raise AuthorityUnavailable("prepared effect changed before claim commit")
                        db.execute(
                            "UPDATE authority_effects SET execution_seq=? "
                            "WHERE namespace=? AND effect_id=?",
                            (pending.expected_execution_seq, self.namespace,
                             pending.permit.effect_id))
                    else:
                        predecessor, _, _ = self._check_observed_source_locked(
                            db, pending, subject)
                        effect = db.execute(
                            "SELECT state,conflict_keys_json,execution_seq FROM authority_effects "
                            "WHERE namespace=? AND effect_id=?",
                            (self.namespace, pending.permit.effect_id)).fetchone()
                        if effect != ("unresolved", mutation[5],
                                      predecessor.pending.expected_execution_seq):
                            raise AuthorityUnavailable("claimed effect changed before observation commit")
                        db.execute(
                            "UPDATE authority_effects SET execution_seq=? "
                            "WHERE namespace=? AND effect_id=?",
                            (pending.expected_execution_seq, self.namespace,
                             pending.permit.effect_id))
                    db.execute("UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=?", (
                        pending.expected_execution_seq,
                        pending.expected_append_digest,
                        self.core._new_nonce(), self.namespace))
                    self.core._event(db, self.namespace, "execution_v2_" + pending.phase,
                                     pending.permit.generation,
                                     (pending.mutation_id, pending.request_digest,
                                      pending.expected_append_digest))
                    after = self.core._anchor(db, self.namespace,
                                              self.core._row(db, self.namespace))
                    state = "committed"
                else:
                    after = pending.before_anchor
                    state = "cancelled_unappended"
                receipt = MutationReceiptV2(
                    pending=pending, after_anchor=after,
                    updated_revision=pending.permit.revision + 1,
                    durable_state=state)
                updated = self.fences.finish_mutation_locked(
                    db, receipt, subject=subject)
                return receipt, updated

    def observe_prepared(self, *, credential, subject: str,
                         pending: PendingMutationV2) -> PreparedExecutionObservationV2:
        """Read one prepare against both frozen journals and the Authority CAS.

        An appended prepare means only that the service journal recorded it.
        It never proves a platform send, observation, or settlement.
        """
        if type(pending) is not PendingMutationV2 or pending.phase != "prepared":
            raise AuthorityUnavailable("only prepared dispatch observation is supported")
        identifier(subject, "subject")
        self.core._require(credential, "execution", self.namespace,
                           pending.permit.holder)
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks dispatch observation")
                inspection = self.journal.inspect_expected(pending)
                if inspection.following_count > 1:
                    raise AuthorityUnavailable("extra execution append quarantines prepared observation")
                with self.core._tx() as db:
                    self._require_v2_mode_locked(db)
                    self.fences._check_schema(db)
                    self._check_deletion_locked(db, deletion_head)
                    mutation = self._load_mutation_locked(db, pending, subject)
                    kind, saved, receipt, updated = self.fences._decode_mutation_row(mutation)
                    if kind != "execution" or saved != pending or mutation[5] == "null":
                        raise AuthorityUnavailable("prepared mutation ledger is invalid")
                    row = self.core._row(db, self.namespace)
                    effect = db.execute(
                        "SELECT state,conflict_keys_json,execution_seq FROM authority_effects "
                        "WHERE namespace=? AND effect_id=?",
                        (self.namespace, pending.permit.effect_id)).fetchone()
                    if mutation[4] == "pending":
                        self._check_core_owner(db, pending.permit)
                        self._check_fence_locked(db, pending.permit, subject,
                                                 pending=pending)
                        if effect is not None:
                            raise AuthorityUnavailable("pending prepare has conflicting effect history")
                    elif mutation[4] == "committed":
                        if (inspection.following_count != 1
                                or effect != ("unresolved", mutation[5],
                                              pending.expected_execution_seq)
                                or self.core._anchor(db, self.namespace, row)
                                != receipt.after_anchor):
                            raise AuthorityUnavailable("committed prepare differs from Authority effect")
                    elif mutation[4] == "cancelled_unappended":
                        if (inspection.following_count != 0 or effect is not None
                                or self.core._anchor(db, self.namespace, row)
                                != receipt.after_anchor):
                            raise AuthorityUnavailable("cancelled prepare has a journal append")
                    else:
                        raise AuthorityUnavailable("unknown prepared mutation state")
                    if mutation[4] != "pending":
                        fence = self.fences._row(db, pending.permit.operation_id)
                        if (fence is None or fence[10] is not None
                                or self.fences._permit(fence) != updated):
                            raise AuthorityUnavailable("completed prepare fence differs")
                    result = (receipt, updated) if receipt is not None else None
                    return PreparedExecutionObservationV2(inspection.first_append, result)

    def execution_prepare(self, *, credential, subject: str,
                          permit: FencePermitV2, mutation_id: str,
                          footprint: RecoveryConstraintFootprint):
        """Convenience path; stable mutation ID makes response loss retryable."""
        self.core._require(credential, "execution", self.namespace,
                           permit.holder)
        pending = self._build_pending(permit, mutation_id, footprint)
        completed = None
        with self.core._tx() as db:
            self._require_v2_mode_locked(db)
            mutation = self.fences.mutation_locked(db, mutation_id)
            if mutation is not None:
                row = self._load_mutation_locked(db, pending, subject)
                completed = self._completed_result(row)
        if completed is not None:
            return self.reconcile_mutation(
                credential=credential, subject=subject, pending=pending)
        if mutation is None:
            self.prepare_pending(credential=credential, subject=subject,
                                 permit=permit, mutation_id=mutation_id,
                                 footprint=footprint)
        self.append_pending(pending, credential=credential, subject=subject)
        return self.reconcile_mutation(
            credential=credential, subject=subject, pending=pending)

    def execution_claim(self, *, credential, subject: str,
                        prepared_receipt: MutationReceiptV2,
                        binding: ExecutionBindingV1):
        """Historical V1 claim path; no platform call."""
        if type(binding) is not ExecutionBindingV1:
            raise AuthorityUnavailable("V1 claim requires an explicit V1 binding")
        return self._execution_claim(credential=credential, subject=subject,
                                     prepared_receipt=prepared_receipt, binding=binding)

    def execution_claim_v2(self, *, credential, subject: str,
                           prepared_receipt: MutationReceiptV2,
                           binding: ExecutionBindingV2):
        """Persist the full V2 admission identity in the claimed journal entry."""
        if type(binding) is not ExecutionBindingV2:
            raise AuthorityUnavailable("V2 claim requires complete V2 admission binding")
        return self._execution_claim(credential=credential, subject=subject,
                                     prepared_receipt=prepared_receipt, binding=binding)

    def _execution_claim(self, *, credential, subject: str,
                         prepared_receipt: MutationReceiptV2,
                         binding: ExecutionBindingV1 | ExecutionBindingV2):
        pending = self.prepare_claim_pending(
            credential=credential, subject=subject,
            prepared_receipt=prepared_receipt, binding=binding)
        with self.core._tx() as db:
            mutation = self._load_mutation_locked(db, pending, subject)
            completed = self._completed_result(mutation)
        if completed is not None:
            return self.reconcile_mutation(
                credential=credential, subject=subject, pending=pending)
        self.append_pending(pending, credential=credential, subject=subject)
        return self.reconcile_mutation(
            credential=credential, subject=subject, pending=pending)

    def _check_handoff_current_locked(self, db, *, permit: FencePermitV2,
                                      subject: str, claimed_receipt: MutationReceiptV2,
                                      deletion_head, execution_head) -> None:
        """P2/current-state barrier used before and after the graph claim."""
        self._require_v2_mode_locked(db)
        self.fences._check_schema(db)
        self._check_deletion_locked(db, deletion_head)
        if (execution_head.journal_id, execution_head.seq,
                execution_head.digest) != (
                    permit.pinned_anchor.execution_journal_id,
                    permit.pinned_anchor.execution_seq,
                    permit.pinned_anchor.execution_digest):
            raise AuthorityUnavailable("claimed append is no longer current")
        self._check_execution_head_locked(db, execution_head)
        self._check_core_owner(db, permit)
        self._check_fence_locked(db, permit, subject)
        original = self._load_mutation_locked(db, claimed_receipt.pending, subject)
        if self._completed_result(original) != (claimed_receipt, permit):
            raise AuthorityUnavailable("original committed claim changed")
        effect = db.execute(
            "SELECT state,execution_seq FROM authority_effects "
            "WHERE namespace=? AND effect_id=?",
            (self.namespace, permit.effect_id)).fetchone()
        if effect != ("unresolved", claimed_receipt.after_anchor.execution_seq):
            raise AuthorityUnavailable("current effect claim differs")

    def begin_handoff(self, *, credential, subject: str,
                      claimed_receipt: MutationReceiptV2,
                      handoff_id: str) -> HandoffStartV2:
        if (type(claimed_receipt) is not MutationReceiptV2
                or type(claimed_receipt.pending.binding) is not ExecutionBindingV1):
            raise AuthorityUnavailable("V1 handoff requires an explicit V1 claim")
        return self._begin_handoff(credential=credential, subject=subject,
                                   claimed_receipt=claimed_receipt, handoff_id=handoff_id)

    def begin_handoff_v2(self, *, credential, subject: str,
                         claimed_receipt: MutationReceiptV2,
                         handoff_id: str) -> HandoffStartV2:
        if (type(claimed_receipt) is not MutationReceiptV2
                or type(claimed_receipt.pending.binding) is not ExecutionBindingV2):
            raise AuthorityUnavailable("V2 handoff requires a complete V2 claim")
        return self._begin_handoff(credential=credential, subject=subject,
                                   claimed_receipt=claimed_receipt, handoff_id=handoff_id)

    def _begin_handoff(self, *, credential, subject: str,
                       claimed_receipt: MutationReceiptV2,
                       handoff_id: str) -> HandoffStartV2:
        """Finalize business admission and durably mark one possible handoff.

        No platform call is made. The injected graph authority must atomically
        validate RequiredChecks and reserve an idempotent graph claim using
        this handoff_id before this Authority CAS; missing authority fails closed.
        """
        identifier(subject, "subject")
        identifier(handoff_id, "handoff_id")
        if (type(claimed_receipt) is not MutationReceiptV2
                or claimed_receipt.durable_state != "committed"
                or claimed_receipt.pending.phase != "claimed"):
            raise AuthorityUnavailable("handoff requires committed claim")
        if not callable(self._final_handoff_authorizer):
            raise AuthorityUnavailable("trusted final handoff authorizer is unavailable")
        pending = claimed_receipt.pending
        binding = pending.binding
        assert binding is not None
        permit = replace(pending.permit, revision=claimed_receipt.updated_revision,
                         pinned_anchor=claimed_receipt.after_anchor)
        if permit.subject != subject or permit.namespace != self.namespace:
            raise AuthorityUnavailable("handoff subject or namespace differs")
        self.core._require(credential, "execution", self.namespace, permit.holder)
        claim_digest = canonical_digest(claimed_receipt)
        binding_digest = canonical_digest(binding)
        with self.core._tx() as db:
            self._require_v2_mode_locked(db)
            row = db.execute(
                "SELECT handoff_id,namespace,subject,claim_digest,binding_digest,"
                "graph_claim_ref,permit FROM authority_execution_handoff_starts_v1 "
                "WHERE operation_id=? OR handoff_id=?",
                (permit.operation_id, handoff_id)).fetchone()
            if row is not None:
                if row[:5] != (handoff_id, self.namespace, subject,
                               claim_digest, binding_digest):
                    raise AuthorityUnavailable("handoff replay identity differs")
                saved_permit = decode_bytes(row[6])
                if saved_permit != permit:
                    raise AuthorityUnavailable("handoff replay permit differs")
                return HandoffStartV2(handoff_id, permit.operation_id,
                                      permit.effect_id, self.namespace,
                                      claim_digest, binding_digest,
                                      row[5], permit, replay=True)
        # Check the P2 head, live fence, unresolved effect and exact claim
        # before leaving any durable graph reservation. Release all freezes
        # before the graph callback to avoid GraphWorker/Authority deadlock.
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks handoff")
                execution_head = self.journal.verified_head()
                with self.core._tx() as db:
                    self._check_handoff_current_locked(
                        db, permit=permit, subject=subject,
                        claimed_receipt=claimed_receipt,
                        deletion_head=deletion_head,
                        execution_head=execution_head)
        # External business graph transaction MUST be atomic and idempotent by
        # handoff_id. No Core, deletion, or execution journal lock is held here.
        try:
            graph_claim_ref = self._final_handoff_authorizer(
                binding, claimed_receipt, handoff_id)
        except Exception as exc:
            raise AuthorityUnavailable("final business graph handoff denied") from exc
        identifier(graph_claim_ref, "graph_claim_ref")
        with self.deletion.freeze_writes():
            with self.journal.freeze_writes():
                deletion_head = self.deletion.verified_head()
                if self.deletion.has_deletion_history(self.namespace):
                    raise AuthorityUnavailable("historical deletion closure blocks handoff")
                execution_head = self.journal.verified_head()
                with self.core._tx() as db:
                    self._check_handoff_current_locked(
                        db, permit=permit, subject=subject,
                        claimed_receipt=claimed_receipt,
                        deletion_head=deletion_head,
                        execution_head=execution_head)
                    if db.execute(
                        "SELECT 1 FROM authority_execution_handoff_starts_v1 "
                        "WHERE operation_id=? OR handoff_id=?",
                        (permit.operation_id, handoff_id)).fetchone():
                        raise AuthorityUnavailable("handoff start raced")
                    db.execute(
                        "INSERT INTO authority_execution_handoff_starts_v1"
                        "(handoff_id,operation_id,namespace,subject,claim_digest,"
                        "binding_digest,graph_claim_ref,permit) VALUES(?,?,?,?,?,?,?,?)",
                        (handoff_id, permit.operation_id, self.namespace, subject,
                         claim_digest, binding_digest, graph_claim_ref,
                         canonical_bytes(permit)))
        return HandoffStartV2(handoff_id, permit.operation_id, permit.effect_id,
                              self.namespace, claim_digest, binding_digest,
                              graph_claim_ref, permit)

    def execution_observe(self, *, credential, subject: str,
                          claimed_receipt: MutationReceiptV2,
                          observation: PlatformObservationV1):
        """Record one verified platform report; unknown remains unresolved."""
        pending = self.prepare_observation_pending(
            credential=credential, subject=subject,
            claimed_receipt=claimed_receipt, observation=observation)
        with self.core._tx() as db:
            mutation = self._load_mutation_locked(db, pending, subject)
            completed = self._completed_result(mutation)
        if completed is not None:
            return self.reconcile_mutation(
                credential=credential, subject=subject, pending=pending)
        self.append_pending(pending, credential=credential, subject=subject)
        return self.reconcile_mutation(
            credential=credential, subject=subject, pending=pending)


__all__ = ["AuthorityV2ExecutionBridge", "PreparedExecutionObservationV2",
           "HandoffStartV2"]
