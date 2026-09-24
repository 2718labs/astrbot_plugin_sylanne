"""Authority-local typed preparation; provider handoff remains HOLD."""

from __future__ import annotations

from dataclasses import asdict

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest
from ..host.authority_profile import AdminIngressModelPolicy
from ..model_broker.broker import ModelCallRequest
from .contract import AuthorityUnavailable, identifier
from .current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from .v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressObservationV1,
)
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_fence_service import AuthorityV2FenceService


class AuthorityV2ModelEgressService:
    def __init__(self, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService | None = None, *,
                 graph_verifier: PinnedCurrentModelEgressGraphVerifier | None = None,
                 admin_model_policy: AdminIngressModelPolicy | None = None):
        if type(store) is not AuthorityV2ModelEgressStore:
            raise TypeError("Authority-owned model egress store required")
        if fences is not None and (type(fences) is not AuthorityV2FenceService
                                   or store._db is not fences.core._db
                                   or store._lock is not fences.core._lock):
            raise AuthorityUnavailable("model egress and fence must share Authority DB and lock")
        if (graph_verifier is not None
                and type(graph_verifier) is not PinnedCurrentModelEgressGraphVerifier):
            raise TypeError("administrator-pinned model egress graph verifier required")
        if (admin_model_policy is not None
                and type(admin_model_policy) is not AdminIngressModelPolicy):
            raise TypeError("administrator-installed model policy required")
        self._store = store
        self._fences = fences
        self._graph_verifier = graph_verifier
        self._admin_model_policy = admin_model_policy

    def _admin_model_matches(self, intent: ModelEgressIntentV1,
                             request: ModelCallRequest | None) -> bool:
        """Match a graph-bound request to this Authority installation's policy."""
        policy = self._admin_model_policy
        if type(policy) is not AdminIngressModelPolicy or type(request) is not ModelCallRequest:
            return False
        authority = request.envelope.authority
        return (
            bool(policy.allowed_purposes and policy.allowed_audiences
                 and policy.allowed_privacy_tiers)
            and request.digest == intent.request_digest
            and request.call_id == intent.call_id
            and request.identity.operation_id == intent.operation_id
            and authority.actor == intent.subject
            and authority.issuer_domain == "d11"
            and authority.activation_generation == intent.authority_activation_generation
            and authority.worker_fence == intent.worker_fence
            and authority.purpose in policy.allowed_purposes
            and bool(authority.audience)
            and set(authority.audience) <= set(policy.allowed_audiences)
            and request.privacy_tier == policy.privacy_tier
            and request.privacy_tier in policy.allowed_privacy_tiers
            and request.required_capabilities == frozenset(policy.required_capabilities)
            and (request.provider_id, request.model_id,
                 intent.provider_id, intent.model_id) == (
                    policy.provider_id, policy.model_id,
                    policy.provider_id, policy.model_id)
            and intent.provider_config_digest == policy.provider_config_digest
            and request.max_output_tokens == intent.max_output_tokens
            and request.max_output_tokens <= policy.max_output_tokens
            and request.max_output_tokens <= dict(intent.budget_ceiling).get("output_tokens", 0)
            and request.timeout_seconds == policy.timeout_seconds
        )

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
        """Read the typed identity and fence; prepared plus finished means unsent.

        The recovery DTO alone is passive. Production dispatch remains HOLD.
        """
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
                    or permit.namespace != intent.namespace or row[6] not in {"active", "finished"}
                    or (intent.fence_token, intent.fence_epoch,
                        intent.fence_revision, intent.anchor_digest) !=
                       (permit.token, permit.fence_epoch, permit.revision,
                        canonical_digest(asdict(permit.pinned_anchor)))):
                raise AuthorityUnavailable("typed model fence identity changed")
            if row[6] == "finished":
                status = {"prepared": "not_dispatched", "observed": "completed",
                          "unknown": "unknown"}.get(record.state)
                if (status is None or row[10] is not None or
                        (row[8], row[9]) != (
                            intent.call_id,
                            self._fences.fences.model_terminal_finish_digest(
                                intent, permit, status, record.observation_digest))):
                    raise AuthorityUnavailable("finished model fence lacks original terminal state")
            return record, permit

    def read_observation_fenced(self, *, credential, subject: str,
                                intent: ModelEgressIntentV1) -> ModelEgressObservationV1:
        """No production content read until current graph access is independently verified."""
        raise AuthorityUnavailable(
            "HOLD: trusted current graph read qualification is not integrated"
        )

    def _record_provider_observation(self, *, intent: ModelEgressIntentV1,
                                     response):
        """Unbound responses cannot become Authority facts in a separate commit."""
        raise AuthorityUnavailable(
            "HOLD: unbound provider response cannot be an Authority observation"
        )

    def _finish_observed_fenced(self, *, credential, subject: str, holder: str,
                                intent: ModelEgressIntentV1,
                                expected_anchor: RestoreAnchor):
        """Close a previously durable observation, including crash recovery."""
        if self._fences is None or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor or deletion_history:
                raise AuthorityUnavailable("model finish anchor changed or deletion history exists")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("typed model fence absent")
            permit = self._fences.fences._permit(row)
            self._fences.fences.finish_observed_model_egress_locked(
                db, permit, intent=intent, current_anchor=anchor)
            return self._store.read_locked(db, intent), permit

    def _finish_prepared_not_dispatched_fenced(
            self, *, credential, subject: str, holder: str,
            intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor):
        """Close a prepared unsent call and release its exclusive model fence."""
        if self._fences is None or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor or deletion_history:
                raise AuthorityUnavailable("model finish anchor changed or deletion history exists")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("typed model fence absent")
            permit = self._fences.fences._permit(row)
            record = self._store._finish_not_dispatched_fenced_locked(
                db, intent, permit, self._fences.fences, anchor)
            return record, permit

    def admit_dispatch_once(self, *, credential, subject: str, holder: str,
                            intent: ModelEgressIntentV1,
                            expected_anchor: RestoreAnchor,
                            request: ModelCallRequest | None = None):
        """Grant one internal dispatch admission after graph and policy checks.

        A model fence is held across the independent graph read. Any failure
        closes an untouched prepared call as not_dispatched. This internal
        method is not a production RPC or an executor-result binding.
        """
        if (self._fences is None or type(intent) is not ModelEgressIntentV1
                or type(expected_anchor) is not RestoreAnchor):
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor or deletion_history:
                raise AuthorityUnavailable("model dispatch anchor changed or deletion history exists")
            record = self._store.read_locked(db, intent)
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None or row[6] != "active":
                raise AuthorityUnavailable("model dispatch fence is no longer active")
            permit = self._fences.fences._permit(row)
            self._fences.fences.validate_fence_locked(
                db, permit, subject=subject, current_anchor=anchor)
            if not self._store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("model dispatch lacks original fence binding")
            if record.state != "prepared":
                raise AuthorityUnavailable("model dispatch admission cannot repeat")
        # No journal or Authority lock is held during this independent read.
        try:
            graph_current = (self._graph_verifier is not None
                             and self._graph_verifier.complete_graph_current(intent) is True)
        except Exception:
            graph_current = False
        try:
            policy_current = self._admin_model_matches(intent, request)
        except Exception:
            policy_current = False
        if not graph_current or not policy_current:
            self._finish_prepared_not_dispatched_fenced(
                credential=credential, subject=subject, holder=holder,
                intent=intent, expected_anchor=expected_anchor)
            if not graph_current:
                raise AuthorityUnavailable("HOLD: complete current model graph is unavailable")
            raise AuthorityUnavailable("HOLD: independent administrator model policy is unavailable")
        try:
            with self._fences._frozen() as (db, deletion_head, execution_head,
                                           deletion_history):
                anchor = self._fences._current_locked(
                    db, deletion_head, execution_head, holder=holder,
                    generation=expected_anchor.activation_generation)
                if anchor != expected_anchor or deletion_history:
                    raise AuthorityUnavailable("model dispatch anchor changed or deletion history exists")
                row = self._fences.fences._row(db, intent.operation_id)
                if row is None or self._fences.fences._permit(row) != permit:
                    raise AuthorityUnavailable("original model dispatch permit changed")
                record = self._store._record_dispatch_started_fenced_locked(
                    db, intent, permit, self._fences.fences, anchor)
                return record, permit
        except AuthorityUnavailable:
            # A competing successful CAS must never be reclassified as unsent.
            try:
                self._finish_prepared_not_dispatched_fenced(
                    credential=credential, subject=subject, holder=holder,
                    intent=intent, expected_anchor=expected_anchor)
            except AuthorityUnavailable:
                pass
            raise

    async def begin_handoff(self, request, request_digest):
        raise AuthorityUnavailable(
            "HOLD: independent current graph verifier and fenced executor are not integrated"
        )

    async def finish_handoff(self, start, outcome_digest):
        raise AuthorityUnavailable(
            "HOLD: independent provider observation and fenced finish are not integrated"
        )


__all__ = ["AuthorityV2ModelEgressService"]
