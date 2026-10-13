"""Read two settled natural calls under one fresh private graph scope."""

from __future__ import annotations

from .current_authority_graph_read_v3 import (read_authority_current_point_v3 as _authority_point_v3,
    authority_current_json_v3 as _authority_json_v3,authority_current_json_matches_v3 as _authority_json_matches_v3)

from contextlib import closing
from dataclasses import asdict
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable

from ..graph_types import AtomKey, GraphVersion
from ..model_broker.natural_reply_history_v3 import parse_natural_reply_output_current_v1 as parse_natural_reply_output_v2
from ..model_broker.natural_review import parse_natural_reply_review_output_v1
from ..runtime.d11_types import job_graph_write
from ..runtime.jobs import get_job
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.natural_reply_job_v2 import (
    read_original_call_binding, read_original_preparation,
)
from ..runtime_contracts import (
    NaturalReplyPaidReviewReceiptV2, canonical_digest, canonical_serialize,
)
from .contract import AuthorityUnavailable
from .v2_natural_generation_content_service import (
    PinnedCurrentNaturalGenerationContentVerifierV2,
)
from .v2_natural_paid_review_contract import (
    NaturalPaidReviewCurrentReadRequestV2, NaturalPaidReviewCurrentReadV2,
    natural_paid_review_current_scope_digest_v2,
)
from .v2_natural_review_output_contract import (
    NaturalReviewOriginalOutputV2, from_wire as review_output_from_wire,
)
from .v2_natural_review_output_service import AuthorityV2NaturalReviewOutputService
from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService


class PinnedCurrentNaturalPaidReviewVerifierV2:
    """Rebuild current generation scope and both immutable terminal rows."""

    def __init__(self, graph_db_path: str | Path, *, natural_history_verifier=None):
        path = Path(graph_db_path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("pinned natural paid review graph required")
        self._path = path.resolve(strict=True)
        self._natural_history = natural_history_verifier

    def prepare_read_v1(self, request, *, credential, subject, fences, permit=None, now_utc=None):
        from .current_authority_graph_read_v3 import (require_authority_graph_read_controller_v3,
            begin_authority_graph_read_work_v3)
        controller=require_authority_graph_read_controller_v3(self)
        if controller.fences is not fences:raise AuthorityUnavailable('Authority read crossed its installed original fences')
        if fences.core._runtime_storage_v3 is not None:
            if permit is None:raise AuthorityUnavailable('Authority V3 preparation requires the actual verified original call permit')
            return begin_authority_graph_read_work_v3(self,credential=credential,subject=subject,permit=permit,
                namespace=request.namespace,request=request,parent_original_id=request.c02_operation_id,
                now_utc=now_utc,deadline_utc=None)
        from .d13_natural_frame_verifier_v6 import InstalledAuthorityD13NaturalFrameVerifierV6
        if type(self._natural_history) is InstalledAuthorityD13NaturalFrameVerifierV6:
            return self._natural_history.prepare_continuation_v6(
                self._path, request.generation_content_request.c02_operation_id, credential=credential, subject=subject, fences=fences)
        return (self._natural_history.prepare_continuation_v5(
            self._path, request.generation_content_request.c02_operation_id, credential=credential, subject=subject, fences=fences)
            if self._natural_history is not None else None)

    def read(self, request, generation_intent, generation_receipt,
             review_intent, review_receipt, *, now_utc: float, credential=None, subject=None, fences=None, permit=None, same_batch_prepared=None):
        if (type(request) is not NaturalPaidReviewCurrentReadRequestV2
                or type(now_utc) not in (int, float)
                or not math.isfinite(now_utc)):
            return None
        from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3,read_authority_graph_current_v3
        if type(same_batch_prepared)is AuthorityGraphReadWorkV3:
            work=same_batch_prepared
            if(work.controller.verifier is not self or work.request is not request or work.permit is not permit
                    or work.credential is not credential or work.subject!=subject or work.now_utc!=now_utc):
                raise AuthorityUnavailable('Authority current read changed its original Work/request/permit')
            return read_authority_graph_current_v3(work,lambda db: self._read(db, request, generation_intent, generation_receipt, review_intent, review_receipt, now_utc, self._natural_history, same_batch_prepared.history_continuation.prepared))
        try:
            prepared = (same_batch_prepared if permit is not None else
                self.prepare_read_v1(request, credential=credential, subject=subject, fences=fences))
            with closing(sqlite3.connect(
                    self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                from ..runtime.natural_producer_qualification_v1 import authority_natural_producer_context_v1
                with authority_natural_producer_context_v1(db, fences=fences,
                        credential=credential, subject=subject, permit=permit,
                        namespace=request.namespace, parent_original_id=request.generation_content_request.c02_operation_id):
                    db.execute("BEGIN")
                    try:
                        return self._read(db, request, generation_intent, generation_receipt,
                            review_intent, review_receipt, now_utc, self._natural_history, prepared)
                    finally:
                        db.execute("ROLLBACK")
        except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError,
                AttributeError, RuntimeError):
            return None

    @staticmethod
    def _read(db, request, generation_intent, generation_receipt,
              review_intent, review_receipt, now, natural_history_verifier=None, same_batch_prepared=None):
        gen_request = request.generation_content_request
        review_request = request.review_output_request
        current = PinnedCurrentNaturalGenerationContentVerifierV2._read(
            db, gen_request, generation_intent, generation_receipt, now, natural_history_verifier, same_batch_prepared)
        if current is None:
            return None
        ns = request.namespace
        saved = read_original_preparation(
            db, ns, review_request.parent_original_id, "review")
        generation = read_original_preparation(
            db, ns, review_request.parent_original_id, "generation")
        if (saved is None or saved.state != "terminal"
                or generation is None or generation.state != "terminal"):
            return None
        generation_binding = read_original_call_binding(db, generation)
        if (generation_binding is None
                or generation_binding.typed_request_digest !=
                   gen_request.typed_model_request_digest):
            return None
        seal = saved.seal
        binding = read_original_call_binding(db, saved)
        if binding is None:
            return None
        job = get_job(db, seal.job_id)
        job_write = job_graph_write(job)
        job_row = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((job_write.key.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_write.key.token,),
        ).fetchone())
        seal_digest = canonical_digest(asdict(seal))
        if (job_row is None or job_row[2] != 1
                or _authority_json_v3(job_row[1]) != job_write.value
                or (job.work_kind, job.phase, job.result_ref, job.operation_id,
                    job.budget_ref, job.fence) !=
                   ("natural_review", "completed", seal.call_id,
                    seal.original_operation_id, seal.parent_budget_lease_id,
                    binding.worker_fence)
                or (seal.namespace, seal.installation_id, seal.job_id,
                    seal.original_operation_id, seal.acquire_operation_id,
                    seal.call_id, seal.generation_original_operation_id,
                    seal.generation_call_id, seal.generation_output_digest) !=
                   (ns, review_request.installation_id, review_request.job_id,
                    review_request.original_operation_id,
                    review_request.acquire_operation_id,
                    review_request.call_id,
                    gen_request.original_operation_id, gen_request.call_id,
                    gen_request.output_digest)
                or (review_request.generation_original_operation_id,
                    review_request.generation_call_id,
                    review_request.generation_output_digest) !=
                   (gen_request.original_operation_id, gen_request.call_id,
                    gen_request.output_digest)
                or request.review_original_seal_digest != seal_digest
                or review_request.typed_model_request_digest !=
                   binding.typed_request_digest
                or binding.request.digest != binding.typed_request_digest
                or (review_intent.authority_id, review_intent.namespace,
                    review_intent.operation_id, review_intent.call_id,
                    review_intent.job_id, review_intent.request_digest,
                    review_intent.worker_fence,
                    review_intent.budget_reservation_operation_id) !=
                   (review_request.authority_id,
                    review_request.authority_namespace,
                    seal.acquire_operation_id, seal.call_id, seal.job_id,
                    binding.request.digest, binding.worker_fence,
                    seal.reservation_operation_id)):
            return None
        terminal = _authority_point_v3(db,table='graph_natural_review_terminals_v2',columns=('terminal_receipt_digest', 'output_digest', 'output_receipt_json', 'state'),key_columns=('bot', 'persona', 'original_operation_id'),key=tuple(ns.as_tuple + (seal.original_operation_id,)),legacy_reader=lambda: db.execute(
            "SELECT terminal_receipt_digest,output_digest,output_receipt_json,"
            "state FROM graph_natural_review_terminals_v2 WHERE bot=? "
            "AND persona=? AND original_operation_id=?",
            ns.as_tuple + (seal.original_operation_id,),
        ).fetchone())
        if terminal is None or terminal[3] != "committed":
            return None
        output = review_output_from_wire(
            _authority_json_v3(terminal[2]), NaturalReviewOriginalOutputV2)
        review_receipt_digest = canonical_digest(asdict(review_receipt))
        if (output.request.original_operation_id != seal.original_operation_id
                or output.request.call_id != seal.call_id
                or output.original_seal_digest != seal_digest
                or output.typed_model_request_digest != binding.request.digest
                or output.original_intent_digest !=
                   canonical_digest(asdict(review_intent))
                or output.terminal_receipt_digest != review_receipt_digest
                or (terminal[0], terminal[1]) != (
                    request.review_terminal_receipt_digest,
                    request.review_output_digest)
                or (saved.terminal_receipt_digest,
                    saved.terminal_output_digest) != terminal[:2]
                or output.output_digest != terminal[1]
                or output.verdict not in {"pass", "rewrite", "hold"}):
            return None
        cost_id = original_model_cost_operation_id_v1(ns, seal.call_id)
        row = _authority_point_v3(db,table='graph_bundle_operations',columns=('activity_id', 'commit_seq', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=tuple(ns.as_tuple + (cost_id,)),legacy_reader=lambda: db.execute(
            "SELECT activity_id,commit_seq,receipt_json FROM "
            "graph_bundle_operations WHERE bot=? AND persona=? "
            "AND operation_id=?", ns.as_tuple + (cost_id,),
        ).fetchone())
        if row is None:
            return None
        cost_data = _authority_json_v3(row[2])
        if not _authority_json_matches_v3(row[2],cost_data,legacy_serializer=canonical_serialize):
            return None
        cost = OriginalModelCostCommitV1(**cost_data["original_model_cost"])
        cost_atom = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'valid'),key_columns=('token',),key=tuple((cost.cost_ref,)),legacy_reader=lambda: db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (cost.cost_ref,),
        ).fetchone())
        if (cost_data.get("original_intent_digest") !=
                output.original_intent_digest
                or cost_data.get("terminal_receipt_digest") != terminal[0]
                or cost.status != "committed" or cost.operation_id != cost_id
                or cost.call_id != seal.call_id
                or cost.terminal_receipt_digest != terminal[0]
                or cost.commit_seq != row[1]
                or cost_atom is None or cost_atom[1] != 1
                or _authority_point_v3(db,table='graph_events',columns=('1',),key_columns=('bot', 'persona', 'session', 'event_id'),key=tuple(ns.as_tuple + (row[0], cost_id)),legacy_reader=lambda: db.execute(
                    "SELECT 1 FROM graph_events WHERE bot=? AND persona=? "
                    "AND session=? AND event_id=?",
                    ns.as_tuple + (row[0], cost_id),
                ).fetchone()) is None
                or _authority_point_v3(db,table='runtime_budget_operations',columns=('1',),key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=tuple(ns.as_tuple + (seal.reservation_operation_id,))+('settle',),legacy_reader=lambda: db.execute(
                    "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? "
                    "AND persona_id=? AND operation_id=? AND phase='settle'",
                    ns.as_tuple + (seal.reservation_operation_id,),
                ).fetchone()) is None
                or _authority_point_v3(db,table='runtime_budget_reservations',columns=('state',),key_columns=('lease_id', 'operation_id'),key=tuple((seal.parent_budget_lease_id,
                     seal.reservation_operation_id)),legacy_reader=lambda: db.execute(
                    "SELECT state FROM runtime_budget_reservations WHERE "
                    "lease_id=? AND operation_id=?",
                    (seal.parent_budget_lease_id,
                     seal.reservation_operation_id),
                ).fetchone()) != ("settled",)):
            return None
        reads = {item.key.token: item for item in current.read_versions}
        reads[job_write.key.token] = GraphVersion(job_write.key, job_row[0])
        cost_key = AtomKey.from_token(cost.cost_ref)
        reads[cost_key.token] = GraphVersion(cost_key, cost_atom[0])
        versions = tuple(sorted(reads.values(), key=lambda item: item.key.token))
        scope_digest = natural_paid_review_current_scope_digest_v2(
            generation_scope_digest=current.scope_digest,
            review_seal_digest=seal_digest,
            review_terminal_receipt_digest=terminal[0],
            read_versions=versions, graph_epoch=current.graph_epoch,
            access_epoch=current.access_epoch,
            delete_epoch=current.delete_epoch)
        return (current, saved, generation, generation_binding, binding,
                output, versions, scope_digest)


class AuthorityV2NaturalPaidReviewService:
    """Return both observed bodies only within a fresh Authority read fence."""

    def __init__(self, *, generation: AuthorityV2NaturalGenerationOutputService,
                 review: AuthorityV2NaturalReviewOutputService,
                 graph: PinnedCurrentNaturalPaidReviewVerifierV2,
                 trusted_now_utc: Callable[[], float]):
        if (type(generation) is not AuthorityV2NaturalGenerationOutputService
                or type(review) is not AuthorityV2NaturalReviewOutputService
                or type(graph) is not PinnedCurrentNaturalPaidReviewVerifierV2
                or generation._store is not review._store
                or generation._fences is not review._fences
                or generation._graph._path != graph._path
                or review._graph._path != graph._path
                or not callable(trusted_now_utc)):
            raise AuthorityUnavailable("paired natural paid review readers required")
        self._generation, self._review = generation, review
        self._graph, self._clock = graph, trusted_now_utc

    def read_current_natural_paid_review_v2(
        self, *, credential: object,
        request: NaturalPaidReviewCurrentReadRequestV2,
        now_utc: float,
    ) -> NaturalPaidReviewCurrentReadV2:
        generation, review = self._generation, self._review
        fences = generation._fences
        if (type(request) is not NaturalPaidReviewCurrentReadRequestV2
                or request.generation_content_request.authority_namespace !=
                   fences.namespace
                or type(now_utc) not in (int, float)
                or not math.isfinite(now_utc)):
            raise AuthorityUnavailable("installed natural paid review required")
        fences.core._require(
            credential, "read", fences.namespace, generation._holder)
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise AuthorityUnavailable("trusted natural paid review clock unavailable")
        anchor = fences.current_anchor(
            credential=credential, subject=generation._read_subject)
        if anchor.authority_id != request.generation_content_request.authority_id:
            raise AuthorityUnavailable("natural paid review Authority differs")
        gen_intent, gen_receipt, _ = generation._read_original(
            request.generation_content_request, anchor, content=False)
        review_intent, review_receipt, _ = review._read_original(
            request.review_output_request, anchor, content=False)
        prepared_history = None
        permit = fences.begin_fence(
            credential=credential, subject=generation._read_subject,
            holder=generation._holder, operation="read",
            operation_id=request.read_attempt_id, expected_anchor=anchor)
        try:
            fences.validate_fence(
                credential=credential, subject=generation._read_subject,
                permit=permit)
            prepared_history = self._graph.prepare_read_v1(request,credential=credential,
                subject=generation._read_subject,fences=fences,permit=permit,now_utc=now)
            original = self._graph.read(
                request, gen_intent, gen_receipt, review_intent, review_receipt,
                now_utc=now, credential=credential, subject=generation._read_subject, fences=fences,
                permit=permit, same_batch_prepared=prepared_history)
            if original is None:
                raise AuthorityUnavailable("natural paid review current scope unavailable")
            second_gen_intent, second_gen_receipt, gen_observation = (
                generation._read_original(
                    request.generation_content_request, anchor, content=True))
            second_review_intent, second_review_receipt, review_observation = (
                review._read_original(
                    request.review_output_request, anchor, content=True))
            after = self._graph.read(
                request, second_gen_intent, second_gen_receipt,
                second_review_intent, second_review_receipt, now_utc=now,
                credential=credential, subject=generation._read_subject, fences=fences,
                permit=permit, same_batch_prepared=prepared_history)
            if ((second_gen_intent, second_gen_receipt,
                 second_review_intent, second_review_receipt) !=
                (gen_intent, gen_receipt, review_intent, review_receipt)
                    or after != original):
                raise AuthorityUnavailable("natural paid review changed during read")
            (current, saved, generation_saved, generation_binding, binding,
             output, versions, scope) = original
            gen_result, review_result = gen_observation.result, review_observation.result
            if (type(gen_result) is not dict or set(gen_result) != {"text"}
                    or type(gen_result["text"]) is not str
                    or type(review_result) is not dict
                    or set(review_result) != {"text"}
                    or type(review_result["text"]) is not str):
                raise AuthorityUnavailable("natural paid observations differ")
            parsed_generation = parse_natural_reply_output_v2(
                gen_result["text"], generation_saved.frozen)
            parsed_review = parse_natural_reply_review_output_v1(
                review_result["text"], saved.frozen,
                generation_saved.seal, saved.seal)
            generation_output = json.loads(parsed_generation.canonical_output)
            if (parsed_generation.status != "untrusted_content_candidate"
                    or parsed_generation.output_digest !=
                       request.generation_content_request.output_digest
                    or parsed_review.output_digest != request.review_output_digest
                    or parsed_review.verdict != output.verdict
                    or gen_observation.digest != current.observation_digest
                    or review_observation.digest != output.observation_digest):
                raise AuthorityUnavailable("natural paid output differs")
            paid = NaturalReplyPaidReviewReceiptV2(
                request.namespace,
                generation_saved.seal.original_operation_id,
                generation_saved.seal.call_id,
                generation_binding.typed_request_digest,
                request.generation_content_request.terminal_receipt_digest,
                parsed_generation.output_digest,
                saved.seal.original_operation_id, saved.seal.call_id,
                binding.typed_request_digest,
                request.review_terminal_receipt_digest,
                parsed_review.output_digest,
                saved.seal.parent_budget_lease_id,
                generation_saved.seal.reservation_operation_id,
                saved.seal.reservation_operation_id,
                saved.seal.qualified_units_digest,
                saved.seal.review_policy_version,
                parsed_review.verdict, scope)
            response = NaturalPaidReviewCurrentReadV2(
                request, generation_output, parsed_review, paid,
                versions, scope, current.graph_epoch, current.access_epoch,
                current.delete_epoch, current.expires_at_utc)
            fences.validate_fence(
                credential=credential, subject=generation._read_subject,
                permit=permit)
            if self._graph.read(
                    request, gen_intent, gen_receipt, review_intent,
                    review_receipt, now_utc=now,
                    credential=credential, subject=generation._read_subject, fences=fences,
                    permit=permit, same_batch_prepared=prepared_history) != original:
                raise AuthorityUnavailable("natural paid review scope changed after copy")
            self._finish(credential, request.read_attempt_id, permit)
            return response
        except BaseException:
            try:
                self._finish(credential, request.read_attempt_id, permit)
            except Exception:
                pass
            raise
        finally:
            from .current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
            finish_authority_graph_read_work_v3(prepared_history)

    def _finish(self, credential, read_attempt_id, permit):
        generation = self._generation
        basis = {"read_attempt_id": read_attempt_id,
                 "permit": asdict(permit)}
        generation._fences.finish_fence(
            credential=credential, subject=generation._read_subject,
            permit=permit,
            request_id="natural-paid-review-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({
                "action": "finish_natural_paid_review_current_read", **basis}))


__all__ = (
    "PinnedCurrentNaturalPaidReviewVerifierV2",
    "AuthorityV2NaturalPaidReviewService",
)
