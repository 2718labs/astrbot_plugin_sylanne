"""Service-owned local journal append bridge, without a network transport.

The service database transaction remains write-locked while a separate journal
fsyncs. If the journal commits but the authority transaction fails, exact-head
verification closes admissions until ``reconcile_one`` imports that single
verified append. This is for an OS-owned service process, never an in-plugin
authority shortcut.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..runtime.deletion import DeletionHead, DeletionJournal
from ..runtime.restore_anchor import _execution_head_and_continuity
from ..runtime_journal import (
    ExecutionJournal, RecoveryConstraintFootprint, SettlementAuthority,
)
from .contract import AuthorityUnavailable, ContentPermit, JournalHead
from .core import AuthorityServiceCore


_RESOLVED = frozenset({"confirmed_not_dispatched", "constraints_released"})


def constraint_keys_from_footprint(
        footprint: RecoveryConstraintFootprint) -> tuple[str, ...]:
    """Hash minimal conflict identities; an empty set blocks the namespace."""
    if not isinstance(footprint, RecoveryConstraintFootprint):
        raise TypeError("typed recovery footprint required")
    raw = [("conflict", value) for value in footprint.conflict_keys]
    if footprint.contact_id is not None:
        raw.append(("contact", footprint.communication_action, footprint.contact_id))
    raw.extend(("object", value) for value in footprint.object_gate_keys)
    raw.extend(("quota", item.bucket_key, item.window_key)
               for item in footprint.quota_occupancies)
    raw.extend(("resource", item.reservation_ref, item.component_ref)
               for item in footprint.reservations)
    raw.extend(("budget", item.parent_budget_ref) for item in footprint.budgets)
    return tuple(sorted({
        "k:sha256:" + hashlib.sha256(
            json.dumps(item, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        for item in raw
    }))


class LocalJournalBridge:
    """One namespace, one authority DB, two service-owned independent logs."""

    def __init__(self, *, namespace: str, authority_path, deletion_path,
                 execution_path, authorizer, dispatch_verifier,
                 settlement_verifier=None, business_barrier=None,
                 cleanup_verifier=None, create: bool = False):
        if not callable(authorizer) or not callable(dispatch_verifier):
            raise AuthorityUnavailable("authenticated server and D08 dispatch verifier required")
        self.namespace = namespace
        self.deletion_path = Path(deletion_path)
        self.execution_path = Path(execution_path)
        if not create and (not self.deletion_path.exists()
                           or not self.execution_path.exists()):
            raise AuthorityUnavailable("independent journals are absent")
        self.business_barrier = business_barrier
        self.cleanup_verifier = cleanup_verifier
        self.core = AuthorityServiceCore(
            authority_path, authorizer=authorizer,
            deletion_verifier=self._verify_deletion,
            execution_verifier=self._verify_execution,
            effect_verifier=self._verify_effect,
            dispatch_verifier=dispatch_verifier, create=create,
        )
        try:
            # Hold the Authority DB writer barrier even while opening legacy logs.
            # A second process cannot seal between this check and log creation.
            with self.core._legacy_tx():
                self.deletion = DeletionJournal(self.deletion_path, create=create)
                self.execution = ExecutionJournal(
                    self.execution_path, settlement_verifier=settlement_verifier)
        except BaseException:
            self.core.close()
            if hasattr(self, "execution"):
                self.execution.close()
            if hasattr(self, "deletion"):
                self.deletion.close()
            raise

    def _deletion_head(self) -> JournalHead:
        head = self.deletion.latest_head()
        return JournalHead(head.journal_id, head.seq, head.chain_digest)

    def _execution_head(self) -> JournalHead:
        journal_id, seq, digest = _execution_head_and_continuity(self.execution_path)
        return JournalHead(journal_id, seq, digest)

    def _deletion_phase(self) -> str:
        with self.deletion._lock:
            rows = self.deletion._db.execute(
                "SELECT e.phase FROM deletion_events e JOIN ("
                "SELECT operation_id,MAX(seq) seq FROM deletion_events "
                "WHERE namespace=? GROUP BY operation_id) latest ON e.seq=latest.seq",
                (self.namespace,),
            ).fetchall()
        phases = {row[0] for row in rows}
        if "pending" in phases:
            return "pending"
        if "accepted" in phases:
            return "accepted"
        return "clear"

    def _verify_deletion(self, namespace, previous, current, phase) -> bool:
        if namespace != self.namespace or phase != self._deletion_phase():
            return False
        return self.deletion.verify_chain(DeletionHead(
            current.journal_id, current.seq, current.digest))

    def _verify_execution(self, namespace, previous, current, phase) -> bool:
        if namespace != self.namespace or phase is not None:
            return False
        return self._execution_head() == current

    def _effect_record(self, effect_id: str):
        with self.execution._lock:
            row = self.execution._db.execute(
                "SELECT footprint_json FROM execution_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            latest = self.execution._db.execute(
                "SELECT execution_seq,phase FROM execution_entries "
                "WHERE effect_id=? ORDER BY execution_seq DESC LIMIT 1",
                (effect_id,),
            ).fetchone()
        if row is None or latest is None:
            raise AuthorityUnavailable("execution footprint is absent")
        footprint = RecoveryConstraintFootprint._from_json(row[0])
        return footprint, latest

    def _verify_effect(self, namespace, effect_id, state, keys, head) -> bool:
        if namespace != self.namespace or self._execution_head() != head:
            return False
        footprint, latest = self._effect_record(effect_id)
        return (footprint.namespace == namespace
                and footprint.effect_id == effect_id
                and constraint_keys_from_footprint(footprint) == keys
                and latest[0] <= head.seq
                and (latest[1] in _RESOLVED) == (state == "resolved"))

    def register_namespace(self, credential, holder: str):
        core = self.core
        core._require(credential, "install", self.namespace, holder)
        with core._legacy_tx() as db:
            return core._register_namespace_locked(
                db, self.namespace, holder,
                self._deletion_head(), self._execution_head())

    def _apply_deletion(self, db, before, after: JournalHead) -> None:
        core = self.core
        old = core._head(before, "deletion")
        if after.seq != old.seq + 1:
            raise AuthorityUnavailable("deletion recovery requires exactly one new entry")
        phase = self._deletion_phase()
        core._verify_head("deletion", self.namespace, old, after, phase)
        db.execute(
            "UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,"
            "deletion_phase=?,revocation_epoch=revocation_epoch+1,anchor_nonce=? "
            "WHERE namespace=?",
            (after.seq, after.digest, phase, core._new_nonce(), self.namespace),
        )
        core._event(db, self.namespace, "deletion", before[1],
                    (after.seq, after.digest, phase))

    def append_deletion_intent(self, credential, *, operation_id: str,
                               closure_roots: tuple[str, ...], epoch: int,
                               policy_ref: str):
        core = self.core
        core._require(credential, "deletion", self.namespace)
        with core._legacy_tx() as db:
            before = core._row(db, self.namespace)
            core._verify_current_heads(self.namespace, before)
            core._no_permits(db, self.namespace)
            self.deletion.append_intent(
                namespace=self.namespace, operation_id=operation_id,
                closure_roots=closure_roots, epoch=epoch, policy_ref=policy_ref)
            self._apply_deletion(db, before, self._deletion_head())
            return core._anchor(db, self.namespace, core._row(db, self.namespace))

    def advance_deletion(self, credential, operation_id: str, phase: str):
        core = self.core
        core._require(credential, "deletion", self.namespace)
        with core._legacy_tx() as db:
            before = core._row(db, self.namespace)
            core._verify_current_heads(self.namespace, before)
            core._no_permits(db, self.namespace)
            if phase == "accepted":
                if not callable(self.business_barrier):
                    raise AuthorityUnavailable("D06 business barrier verifier is absent")
                self.deletion.advance(operation_id, phase,
                                      business_barrier=self.business_barrier)
            elif phase == "closed":
                if not callable(self.cleanup_verifier):
                    raise AuthorityUnavailable("D06 cleanup verifier is absent")
                self.deletion.advance(operation_id, phase,
                                      cleanup_verifier=self.cleanup_verifier)
            else:
                raise ValueError("unsupported deletion advance phase")
            self._apply_deletion(db, before, self._deletion_head())
            return core._anchor(db, self.namespace, core._row(db, self.namespace))

    def _apply_execution(self, db, before, after: JournalHead,
                         effect_id: str) -> None:
        core = self.core
        old = core._head(before, "execution")
        if after.seq != old.seq + 1:
            raise AuthorityUnavailable("execution recovery requires exactly one new entry")
        core._verify_head("execution", self.namespace, old, after, None)
        footprint, latest = self._effect_record(effect_id)
        if latest[0] != after.seq or footprint.namespace != self.namespace:
            raise AuthorityUnavailable("last execution entry belongs to another effect")
        keys = constraint_keys_from_footprint(footprint)
        state = "resolved" if latest[1] in _RESOLVED else "unresolved"
        if not self._verify_effect(self.namespace, effect_id, state, keys, after):
            raise AuthorityUnavailable("execution footprint verification failed")
        prior = db.execute(
            "SELECT state,conflict_keys_json FROM authority_effects WHERE "
            "namespace=? AND effect_id=?", (self.namespace, effect_id),
        ).fetchone()
        if prior is None:
            if state != "unresolved":
                raise AuthorityUnavailable("effect cannot begin resolved")
            db.execute("INSERT INTO authority_effects VALUES(?,?,?,?,?)",
                       (self.namespace, effect_id, state, json.dumps(keys), after.seq))
        else:
            if prior[0] == "resolved" or tuple(json.loads(prior[1])) != keys:
                raise AuthorityUnavailable("effect footprint changed or was resolved")
            db.execute(
                "UPDATE authority_effects SET state=?,execution_seq=? "
                "WHERE namespace=? AND effect_id=?",
                (state, after.seq, self.namespace, effect_id),
            )
        db.execute(
            "UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,"
            "anchor_nonce=? WHERE namespace=?",
            (after.seq, after.digest, core._new_nonce(), self.namespace),
        )
        core._event(db, self.namespace, "execution", before[1],
                    (effect_id, state, after.seq, after.digest))

    def prepare_execution(self, credential, *, permit: ContentPermit,
                          effect_id: str, command_digest: str,
                          dispatch_generation: int, activation_generation: int,
                          admission_ref: str,
                          footprint: RecoveryConstraintFootprint):
        core = self.core
        keys = constraint_keys_from_footprint(footprint)
        if footprint.namespace != self.namespace or footprint.effect_id != effect_id:
            raise AuthorityUnavailable("execution footprint namespace/effect mismatch")
        core._require(credential, "execution", self.namespace)
        with core._legacy_tx() as db:
            before = core._row(db, self.namespace)
            core._verify_current_heads(self.namespace, before)
            core._admit_dispatch_locked(
                db, credential, namespace=self.namespace, holder=permit.holder,
                generation=activation_generation, effect_id=effect_id,
                conflict_keys=keys, permit=permit)
            entry = self.execution.prepare(
                effect_id=effect_id, command_digest=command_digest,
                dispatch_generation=dispatch_generation,
                activation_generation=activation_generation,
                admission_ref=admission_ref, footprint=footprint)
            self._apply_execution(db, before, self._execution_head(), effect_id)
            return entry

    def observe_execution(self, credential, *, effect_id: str,
                          command_digest: str, phase: str,
                          observation_ref: str):
        core = self.core
        core._require(credential, "execution", self.namespace)
        with core._legacy_tx() as db:
            before = core._row(db, self.namespace)
            core._verify_current_heads(self.namespace, before)
            footprint, _ = self._effect_record(effect_id)
            if footprint.namespace != self.namespace:
                raise AuthorityUnavailable("effect belongs to another namespace")
            entry = self.execution.observe(effect_id, command_digest, phase,
                                           observation_ref)
            self._apply_execution(db, before, self._execution_head(), effect_id)
            return entry

    def release_execution_constraints(self, credential, *, effect_id: str,
                                      command_digest: str,
                                      settlement: SettlementAuthority):
        core = self.core
        core._require(credential, "execution", self.namespace)
        with core._legacy_tx() as db:
            before = core._row(db, self.namespace)
            core._verify_current_heads(self.namespace, before)
            if settlement.namespace != self.namespace:
                raise AuthorityUnavailable("settlement crosses namespace")
            entry = self.execution.release_constraints(
                effect_id, command_digest, settlement)
            self._apply_execution(db, before, self._execution_head(), effect_id)
            return entry

    def reconcile_one(self, credential, kind: str):
        """Import one fsynced append after a service transaction failure."""
        if kind not in {"deletion", "execution"}:
            raise ValueError("unknown journal kind")
        core = self.core
        core._require(credential, "recover", self.namespace)
        with core._legacy_tx() as db:
            before = core._row(db, self.namespace)
            if kind == "deletion":
                head = self._deletion_head()
                event = self.deletion._db.execute(
                    "SELECT namespace FROM deletion_events WHERE seq=?",
                    (head.seq,),
                ).fetchone()
                if event is None or event[0] != self.namespace:
                    raise AuthorityUnavailable("last deletion append is not this namespace")
                self._apply_deletion(db, before, head)
            else:
                head = self._execution_head()
                event = self.execution._db.execute(
                    "SELECT effect_id FROM execution_entries WHERE execution_seq=?",
                    (head.seq,),
                ).fetchone()
                if event is None:
                    raise AuthorityUnavailable("last execution append is absent")
                self._apply_execution(db, before, head, event[0])
            return core._anchor(db, self.namespace, core._row(db, self.namespace))

    def close(self) -> None:
        self.core.close()
        self.deletion.close()
        self.execution.close()


__all__ = ["LocalJournalBridge", "constraint_keys_from_footprint"]
