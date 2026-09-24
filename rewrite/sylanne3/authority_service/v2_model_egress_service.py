"""Authority-local typed preparation; provider handoff remains HOLD."""

from __future__ import annotations

from dataclasses import asdict

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .v2_model_egress_contract import ModelEgressDraftV1, ModelEgressIntentV1
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_fence_service import AuthorityV2FenceService


class AuthorityV2ModelEgressService:
    def __init__(self, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService | None = None):
        if type(store) is not AuthorityV2ModelEgressStore:
            raise TypeError("Authority-owned model egress store required")
        if fences is not None and (type(fences) is not AuthorityV2FenceService
                                   or store._db is not fences.core._db
                                   or store._lock is not fences.core._lock):
            raise AuthorityUnavailable("model egress and fence must share Authority DB and lock")
        self._store = store
        self._fences = fences

    def prepare_fenced(self, *, credential, subject: str, holder: str,
                       draft: ModelEgressDraftV1,
                       expected_anchor: RestoreAnchor):
        """Create a typed record and a fresh model fence in one SQLite commit.

        This is a recovery identity only. It does not attest the complete graph
        request and cannot be used to start a provider dispatch.
        """
        if self._fences is None:
            raise AuthorityUnavailable("protected model fence service unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (type(draft) is not ModelEgressDraftV1
                or type(expected_anchor) is not RestoreAnchor
                or (draft.namespace, draft.subject, draft.authority_id,
                    draft.authority_activation_generation,
                    draft.authority_revocation_epoch,
                    draft.authority_deletion_seq,
                    draft.authority_execution_seq) !=
                   (self._fences.namespace, subject, expected_anchor.authority_id,
                    expected_anchor.activation_generation,
                    expected_anchor.revocation_epoch,
                    expected_anchor.deletion_seq, expected_anchor.execution_seq)
                or expected_anchor.namespace != self._fences.namespace):
            raise AuthorityUnavailable("model intent differs from authenticated Authority anchor")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor or deletion_history:
                raise AuthorityUnavailable("model egress anchor changed or deletion history exists")
            old = self._store._read(db, draft.call_id)
            job_row = db.execute(
                "SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? "
                "AND json_extract(identity_json,'$.job_id')=?",
                (draft.namespace, draft.job_id),
            ).fetchone()
            if job_row is not None and job_row[0] != draft.call_id:
                raise AuthorityUnavailable("model job already has a call identity")
            fence_row = self._fences.fences._row(db, draft.operation_id)
            if old is not None and fence_row is None:
                raise AuthorityUnavailable("passive model record has no atomic fence")
            if old is not None and not self._store.is_fence_bound_locked(db, old.intent):
                raise AuthorityUnavailable("passive model record has no atomic binding")
            if old is None and fence_row is not None:
                raise AuthorityUnavailable("model fence operation already exists without typed record")
            if old is not None and ModelEgressDraftV1.from_intent(old.intent) != draft:
                raise AuthorityUnavailable("model egress identity changed")
            permit = self._fences.fences.begin_fence_locked(
                db, subject=subject, holder=holder, operation="model_egress",
                current_anchor=anchor, operation_id=draft.operation_id)
            intent = ModelEgressIntentV1(
                **asdict(draft), fence_token=permit.token,
                fence_epoch=permit.fence_epoch, fence_revision=permit.revision,
                anchor_digest=canonical_digest(asdict(permit.pinned_anchor)))
            if old is not None and old.intent != intent:
                raise AuthorityUnavailable("persisted model fence differs from typed record")
            record = self._store.prepare_locked(db, intent)
            if old is None:
                self._store.bind_fence_locked(db, intent)
            return record, permit

    def recover_fenced(self, *, credential, subject: str,
                       intent: ModelEgressIntentV1):
        """Read only the exact typed identity and its persisted model fence."""
        if self._fences is None or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "current", self._fences.namespace)
        with self._fences.core._tx() as db:
            self._fences._require_mode(db)
            record = self._store.read_locked(db, intent)
            if not self._store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("model fence was not atomically bound")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("typed model fence absent")
            permit = self._fences.fences._permit(row)
            if (permit.operation != "model_egress" or permit.subject != subject
                    or permit.namespace != intent.namespace or row[6] != "active"
                    or (intent.fence_token, intent.fence_epoch,
                        intent.fence_revision, intent.anchor_digest) !=
                       (permit.token, permit.fence_epoch, permit.revision,
                        canonical_digest(asdict(permit.pinned_anchor)))):
                raise AuthorityUnavailable("typed model fence identity changed")
            return record, permit

    async def begin_handoff(self, request, request_digest):
        raise AuthorityUnavailable(
            "HOLD: independent current graph verifier and fenced executor are not integrated"
        )

    async def finish_handoff(self, start, outcome_digest):
        raise AuthorityUnavailable(
            "HOLD: independent provider observation and fenced finish are not integrated"
        )


__all__ = ["AuthorityV2ModelEgressService"]
