"""Authority-issued, content-free proof of one finished worker result handoff."""

from __future__ import annotations

from dataclasses import asdict

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .v2_worker_model_result_read_service import AuthorityV2WorkerModelResultReadService
from .v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1, WorkerResultReadFactV1,
)


class AuthorityV2WorkerResultReadFactService:
    """A designated installed C02 committer queries the original Authority DB.

    The graph check is outside the Authority/journal locks.  Both Authority
    snapshots check the exact original read and model finish plus the live C02
    write fence; a later Graph transaction still must recheck graph currentness.
    """

    def __init__(self, *, worker_reads: AuthorityV2WorkerModelResultReadService,
                 committer_subject: str, committer_holder: str):
        if type(worker_reads) is not AuthorityV2WorkerModelResultReadService:
            raise TypeError("trusted worker result read composition required")
        identifier(committer_subject, "committer_subject")
        identifier(committer_holder, "committer_holder")
        self._reads = worker_reads
        self._committer_subject = committer_subject
        self._committer_holder = committer_holder

    def _require(self, credential, request: WorkerResultReadFactRequestV1):
        if type(request) is not WorkerResultReadFactRequestV1:
            raise AuthorityUnavailable("typed worker result fact request required")
        read = request.read_request
        write = request.write_permit
        if (read.authority_namespace != self._reads._fences.namespace
                or read.installation_id != self._reads._installation_id
                or (write.subject, write.holder) !=
                   (self._committer_subject, self._committer_holder)
                or write.operation_id != read.consumer_operation_id):
            raise AuthorityUnavailable("C02 committer or operation differs")
        self._reads._fences.core._require(
            credential, "write", read.authority_namespace, self._committer_holder)

    def _snapshot(self, request: WorkerResultReadFactRequestV1):
        reads = self._reads
        fences = reads._fences
        original = request.read_request
        write = request.write_permit
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head,
                holder=self._committer_holder, generation=write.generation)
            if (history or anchor != write.pinned_anchor
                    or (anchor.authority_id, anchor.namespace) !=
                       (original.authority_id, original.authority_namespace)):
                raise AuthorityUnavailable("C02 fact current anchor unavailable")
            fences.fences.validate_fence_locked(
                db, write, subject=self._committer_subject, current_anchor=anchor)
            write_row = fences.fences._row(db, write.operation_id)
            if (write_row is None or write_row[6] != "active"
                    or write_row[10] is not None
                    or fences.fences._permit(write_row) != write):
                raise AuthorityUnavailable("C02 write fence is not active")
            read_row = fences.fences._row(db, original.read_attempt_id)
            attempt = reads._attempts._read_locked(db, original.read_attempt_id)
            if read_row is None or attempt is None:
                raise AuthorityUnavailable("original worker handoff absent")
            read_permit = fences.fences._permit(read_row)
            finish_id, finish_digest = reads._finish_identity(original, read_permit)
            if (attempt.request != original or attempt.state != "finished"
                    or attempt.result_digest is None
                    or attempt.permit_digest != canonical_digest(asdict(read_permit))
                    or (read_permit.operation, read_permit.subject,
                        read_permit.holder, read_permit.operation_id,
                        read_permit.pinned_anchor) !=
                       ("read", reads._read_subject, reads._holder,
                        original.read_attempt_id, anchor)
                    or read_row[6] != "finished" or read_row[10] is not None
                    or read_row[8:10] != (finish_id, finish_digest)):
                raise AuthorityUnavailable("worker result handoff is not finished")
            intent, receipt, _ = reads._terminal_locked(
                db, original, anchor, content=False)
            fact = WorkerResultReadFactV1(
                original, original.digest, read_permit, attempt.permit_digest,
                finish_id, finish_digest, attempt.result_digest,
                canonical_digest(asdict(intent)), receipt, write,
                canonical_digest(asdict(write)))
            return intent, fact

    def current(self, *, credential,
                request: WorkerResultReadFactRequestV1) -> WorkerResultReadFactV1:
        """Fail closed unless both Authority snapshots and the graph agree."""
        self._require(credential, request)
        intent, fact = self._snapshot(request)
        if self._reads._graph.current(
                request.read_request, intent, fact.read_permit) is not True:
            raise AuthorityUnavailable("current worker graph qualification unavailable")
        intent_after, fact_after = self._snapshot(request)
        if intent_after != intent or fact_after != fact:
            raise AuthorityUnavailable("worker result fact changed during graph check")
        return fact


__all__ = ("AuthorityV2WorkerResultReadFactService",)
