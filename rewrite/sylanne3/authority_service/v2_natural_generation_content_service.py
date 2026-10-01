"""Release the original paid generation text only for a current review read.

The original cost/terminal is historical. The private route, D07 focus,
qualified D06 closure and adopted D08 plan are independently read again in
one pinned graph snapshot before any text leaves Authority.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable

from ..domains.d08.natural_plan import decode_natural_plan_v2
from ..graph_types import AtomKey, GraphVersion
from ..model_broker.natural_reply_history_v3 import parse_natural_reply_output_current_v1 as parse_natural_reply_output_v2
from ..runtime.d11_types import job_graph_write
from ..runtime.jobs import get_job
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.natural_generation_issue_v2 import read_original_scoped_query_proof_v2
from ..runtime.natural_reply_job_v2 import (
    read_original_call_binding, read_original_preparation,
)
from ..runtime.natural_scoped_query_proof_v2 import (
    assert_natural_scoped_query_current_v2,
)
from ..runtime_contracts import VersionedRef, canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from .v2_model_egress_contract import ModelEgressIntentV1, ModelTerminalReceiptV2
from .v2_natural_generation_content_contract import (
    NaturalGenerationContentReadRequestV2, NaturalGenerationCurrentContentV2,
    natural_generation_current_scope_digest_v2,
)
from .v2_natural_generation_output_contract import (
    NaturalGenerationOriginalOutputV2, from_wire as output_from_wire,
)
from .v2_natural_generation_output_service import (
    AuthorityV2NaturalGenerationOutputService,
)


@dataclass(frozen=True, slots=True)
class CurrentNaturalGenerationGraphReadV2:
    frozen: object
    observation_digest: str
    output_digest: str
    scope_digest: str
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    expires_at_utc: float


class PinnedCurrentNaturalGenerationContentVerifierV2:
    """Rebuild original terminal and current review scope in one graph tx."""

    def __init__(self, graph_db_path: str | Path, *, natural_history_verifier=None):
        path = Path(graph_db_path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("pinned natural graph database required")
        self._path = path.resolve(strict=True)
        self._natural_history = natural_history_verifier

    def read(self, request: NaturalGenerationContentReadRequestV2,
             intent: ModelEgressIntentV1,
             receipt: ModelTerminalReceiptV2, *,
             now_utc: float) -> CurrentNaturalGenerationGraphReadV2 | None:
        if (type(request) is not NaturalGenerationContentReadRequestV2
                or type(intent) is not ModelEgressIntentV1
                or type(receipt) is not ModelTerminalReceiptV2
                or type(now_utc) not in (int, float)
                or not math.isfinite(now_utc)):
            return None
        try:
            with closing(sqlite3.connect(
                    self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._read(db, request, intent, receipt, now_utc, self._natural_history)
                finally:
                    db.execute("ROLLBACK")
        except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError,
                AttributeError, RuntimeError):
            return None

    @staticmethod
    def _read(db, request, intent, receipt, now, natural_history_verifier=None):
        ns = request.namespace
        saved = read_original_preparation(
            db, ns, request.c02_operation_id, "generation")
        if saved is None or saved.state != "terminal":
            return None
        seal, frozen = saved.seal, saved.frozen
        from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4
        if type(frozen) is FrozenNaturalReplyRequestV4:
            from .d13_natural_frame_verifier_v1 import InstalledAuthorityD13NaturalFrameVerifierV1
            if (type(natural_history_verifier) is not InstalledAuthorityD13NaturalFrameVerifierV1
                    or natural_history_verifier.current_v4(db, frozen=frozen,
                        parent_original_id=request.c02_operation_id, now_utc=now) is None):
                return None
        binding = read_original_call_binding(db, saved)
        if binding is None:
            return None
        call = binding.request
        job = get_job(db, seal.job_id)
        seal_digest = canonical_digest(asdict(seal))
        if ((seal.namespace, seal.c02_operation_id, seal.source_ref,
             seal.installation_id, seal.job_id, seal.original_operation_id,
             seal.acquire_operation_id, seal.call_id) !=
            (ns, request.c02_operation_id, request.source_ref,
             request.installation_id, request.job_id,
             request.original_operation_id, request.acquire_operation_id,
             request.call_id)
                or request.original_seal_digest != seal_digest
                or request.typed_model_request_digest != call.digest
                or binding.typed_request_digest != call.digest
                or (job.work_kind, job.phase, job.result_ref,
                    job.operation_id, job.budget_ref, job.fence) !=
                   ("natural_generation", "completed", seal.call_id,
                    seal.original_operation_id, seal.parent_budget_lease_id,
                    binding.worker_fence)
                or (intent.authority_id, intent.namespace,
                    intent.operation_id, intent.call_id, intent.job_id,
                    intent.request_digest, intent.worker_fence,
                    intent.budget_reservation_operation_id) !=
                   (request.authority_id, request.authority_namespace,
                    seal.acquire_operation_id, seal.call_id, seal.job_id,
                    call.digest, binding.worker_fence,
                    seal.reservation_operation_id)):
            return None
        job_write = job_graph_write(job)
        job_atom = db.execute(
            "SELECT value,valid FROM graph_atoms WHERE token=?",
            (job_write.key.token,),
        ).fetchone()
        if (job_atom is None or job_atom[1] != 1
                or json.loads(job_atom[0]) != job_write.value):
            return None
        terminal = db.execute(
            "SELECT terminal_receipt_digest,output_digest,output_receipt_json,"
            "state FROM graph_natural_generation_terminals_v2 WHERE bot=? "
            "AND persona=? AND original_operation_id=?",
            ns.as_tuple + (seal.original_operation_id,),
        ).fetchone()
        if terminal is None or terminal[3] != "committed":
            return None
        output = output_from_wire(
            json.loads(terminal[2]), NaturalGenerationOriginalOutputV2)
        if (output.request.original_operation_id != seal.original_operation_id
                or output.request.call_id != seal.call_id
                or output.original_seal_digest != seal_digest
                or output.typed_model_request_digest != call.digest
                or output.terminal_receipt_digest != request.terminal_receipt_digest
                or output.output_digest != request.output_digest
                or output.status != "untrusted_content_candidate"
                or (terminal[0], terminal[1]) != (
                    request.terminal_receipt_digest, request.output_digest)
                or (saved.terminal_receipt_digest,
                    saved.terminal_output_digest) != terminal[:2]
                or canonical_digest(asdict(receipt)) != terminal[0]
                or output.original_intent_digest != canonical_digest(asdict(intent))):
            return None
        cost_id = original_model_cost_operation_id_v1(ns, seal.call_id)
        row = db.execute(
            "SELECT activity_id,commit_seq,receipt_json FROM "
            "graph_bundle_operations WHERE bot=? AND persona=? AND "
            "operation_id=?", ns.as_tuple + (cost_id,),
        ).fetchone()
        if row is None:
            return None
        cost_data = json.loads(row[2])
        if canonical_serialize(cost_data) != row[2]:
            return None
        cost = OriginalModelCostCommitV1(**cost_data["original_model_cost"])
        if (cost_data.get("original_intent_digest") !=
                output.original_intent_digest
                or cost_data.get("terminal_receipt_digest") != terminal[0]
                or cost.status != "committed" or cost.operation_id != cost_id
                or cost.call_id != seal.call_id
                or cost.terminal_receipt_digest != terminal[0]
                or cost.commit_seq != row[1]
                or db.execute(
                    "SELECT 1 FROM graph_events WHERE bot=? AND persona=? "
                    "AND session=? AND event_id=?",
                    ns.as_tuple + (row[0], cost_id),
                ).fetchone() is None
                or db.execute(
                    "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1",
                    (cost.cost_ref,),
                ).fetchone() is None
                or db.execute(
                    "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? "
                    "AND persona_id=? AND operation_id=? AND phase='settle'",
                    ns.as_tuple + (seal.reservation_operation_id,),
                ).fetchone() is None
                or db.execute(
                    "SELECT state FROM runtime_budget_reservations WHERE "
                    "lease_id=? AND operation_id=?",
                    (seal.parent_budget_lease_id,
                     seal.reservation_operation_id),
                ).fetchone() != ("settled",)):
            return None
        graph_epoch_row = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            ns.as_tuple,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns.as_tuple,
        ).fetchone()
        if graph_epoch_row is None or epochs is None:
            return None
        graph_epoch = graph_epoch_row[0]
        proof = read_original_scoped_query_proof_v2(db, saved)
        assert_natural_scoped_query_current_v2(db, proof, now_utc=now)
        plan = frozen.input.plan
        if (request.scene_id != plan.scene_id
                or request.audience_id != plan.audience_id
                or now >= min(plan.valid_until_utc,
                              frozen.input.expires_at_utc)):
            return None
        # The same qualified D07 reader that supplies source/access/correction
        # closure is rebuilt here from current graph rows, not W01's guard.
        snapshot, attention = (
            PinnedCurrentModelEgressGraphVerifier._reply_snapshot(
                db, ns, seal.source_ref, graph_epoch, now))
        plan_key = AtomKey.from_token(plan.plan_ref.ref)
        plan_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (plan_key.token,),
        ).fetchone()
        if (plan_row is None or plan_row[0] != plan.plan_ref.version
                or plan_row[2] != 1):
            return None
        adopted = decode_natural_plan_v2(json.loads(plan_row[1]))
        if (adopted.c02_operation_id != request.c02_operation_id
                or adopted.source_ref.ref != seal.source_ref
                or adopted.source_ref.version !=
                   next((row.revision for row in snapshot.versions
                         if row.key.token == seal.source_ref), None)
                or adopted.focus_ref != VersionedRef(
                    attention.focus_version.key.token,
                    attention.focus_version.revision)
                or adopted.ticket_ref != VersionedRef(
                    attention.ticket_version.key.token,
                    attention.ticket_version.revision)
                or adopted.scene_id != plan.scene_id
                or adopted.audience_id != plan.audience_id
                or adopted.scene_ref != plan.scene_ref
                or adopted.audience_ref != plan.audience_ref
                or adopted.plan_id != plan_key.name
                or adopted.final_activity_id != plan.final_activity_id
                or adopted.final_operation_id != plan.final_operation_id
                or adopted.final_effect_id != plan.final_effect_id
                or adopted.parent_budget_lease_id != seal.parent_budget_lease_id
                or adopted.generation_reservation_id !=
                   seal.reservation_operation_id
                or adopted.required_slots != plan.required_slots
                or adopted.allowed_speech_acts != plan.allowed_speech_acts
                or adopted.promise_grants != plan.promise_grants
                or adopted.qualified_units_digest != canonical_digest(plan.units)
                or adopted.d06_qualification_digests != tuple(sorted({
                    unit.qualification_digest for unit in plan.units
                    if unit.d06_claim_kind is not None}))
                or adopted.qualification_refs != tuple(dict.fromkeys(
                    unit.qualification_ref for unit in plan.units
                    if unit.qualification_ref is not None))
                or adopted.valid_until_utc != plan.valid_until_utc):
            return None
        reads: dict[str, GraphVersion] = {
            item.key.token: item for item in snapshot.versions}
        reads[plan_key.token] = GraphVersion(plan_key, plan_row[0])
        for evidence in (*proof.account_matches, *proof.role_matches,
                         *proof.boundary_matches, *proof.d06_closure):
            previous = reads.get(evidence.token)
            if previous is not None and previous.revision != evidence.revision:
                return None
            reads[evidence.token] = GraphVersion(
                AtomKey.from_token(evidence.token), evidence.revision)
        for item in adopted.qualified_read_versions:
            previous = reads.get(item.key.token)
            if previous is not None and previous.revision != item.revision:
                return None
            row = db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (item.key.token,),
            ).fetchone()
            if ((item.revision == 0 and row is not None)
                    or (item.revision > 0 and row != (item.revision, 1))):
                return None
            reads[item.key.token] = item
        versions = tuple(sorted(reads.values(), key=lambda item: item.key.token))
        scope_digest = natural_generation_current_scope_digest_v2(
            original_seal_digest=seal_digest,
            scoped_proof_digest=proof.semantic_digest,
            adopted_plan_digest=canonical_digest(asdict(adopted)),
            read_versions=versions, graph_epoch=graph_epoch,
            access_epoch=epochs[0], delete_epoch=epochs[1],
            scene_id=plan.scene_id, audience_id=plan.audience_id)
        return CurrentNaturalGenerationGraphReadV2(
            frozen, output.observation_digest, output.output_digest,
            scope_digest, versions, graph_epoch, epochs[0], epochs[1],
            min(plan.valid_until_utc, frozen.input.expires_at_utc))


class AuthorityV2NaturalGenerationContentService:
    """A local review-only read; mTLS transport is installed separately."""

    def __init__(self, *, original: AuthorityV2NaturalGenerationOutputService,
                 graph: PinnedCurrentNaturalGenerationContentVerifierV2,
                 trusted_now_utc: Callable[[], float]):
        if (type(original) is not AuthorityV2NaturalGenerationOutputService
                or type(graph) is not PinnedCurrentNaturalGenerationContentVerifierV2
                or original._graph._path != graph._path
                or not callable(trusted_now_utc)):
            raise AuthorityUnavailable("pinned natural content reader required")
        self._original, self._graph, self._clock = original, graph, trusted_now_utc

    def read_current_natural_generation_content_v2(
        self, *, credential: object,
        request: NaturalGenerationContentReadRequestV2, now_utc: float,
    ) -> NaturalGenerationCurrentContentV2:
        original, fences = self._original, self._original._fences
        if (type(request) is not NaturalGenerationContentReadRequestV2
                or request.authority_namespace != fences.namespace
                or request.installation_id != original._installation_id
                or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
            raise AuthorityUnavailable("installed natural content read required")
        fences.core._require(
            credential, "read", request.authority_namespace, original._holder)
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise AuthorityUnavailable("trusted natural content clock unavailable")
        anchor = fences.current_anchor(
            credential=credential, subject=original._read_subject)
        if anchor.authority_id != request.authority_id:
            raise AuthorityUnavailable("natural content Authority identity differs")
        intent, receipt, _ = original._read_original(
            request, anchor, content=False)
        current = self._graph.read(request, intent, receipt, now_utc=now)
        if current is None:
            raise AuthorityUnavailable("natural current review scope unavailable")
        permit = fences.begin_fence(
            credential=credential, subject=original._read_subject,
            holder=original._holder, operation="read",
            operation_id=request.read_attempt_id, expected_anchor=anchor)
        try:
            fences.validate_fence(
                credential=credential, subject=original._read_subject,
                permit=permit)
            second_intent, second_receipt, observation = original._read_original(
                request, anchor, content=True)
            after = self._graph.read(
                request, second_intent, second_receipt, now_utc=now)
            if (second_intent != intent or second_receipt != receipt
                    or after != current
                    or observation.digest != current.observation_digest):
                raise AuthorityUnavailable("natural review scope changed during read")
            result = observation.result
            if (type(result) is not dict or set(result) != {"text"}
                    or type(result["text"]) is not str):
                raise AuthorityUnavailable("natural provider result shape differs")
            parsed = parse_natural_reply_output_v2(
                result["text"], current.frozen)
            if (parsed.status != "untrusted_content_candidate"
                    or parsed.output_digest != request.output_digest):
                raise AuthorityUnavailable("natural paid output differs")
            response = NaturalGenerationCurrentContentV2(
                request, result["text"], observation.digest,
                parsed.output_digest, current.scope_digest,
                current.read_versions, current.graph_epoch,
                current.access_epoch, current.delete_epoch,
                current.expires_at_utc)
            fences.validate_fence(
                credential=credential, subject=original._read_subject,
                permit=permit)
            if self._graph.read(request, intent, receipt, now_utc=now) != current:
                raise AuthorityUnavailable("natural review scope changed after copy")
            self._finish_content(credential, request.read_attempt_id, permit)
            return response
        except BaseException:
            try:
                self._finish_content(credential, request.read_attempt_id, permit)
            except Exception:
                pass
            raise

    def _finish_content(self, credential, read_attempt_id, permit) -> None:
        original = self._original
        basis = {"read_attempt_id": read_attempt_id,
                 "permit": asdict(permit)}
        original._fences.finish_fence(
            credential=credential, subject=original._read_subject,
            permit=permit,
            request_id="natural-content-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({
                "action": "finish_natural_generation_content_read", **basis}))


__all__ = (
    "CurrentNaturalGenerationGraphReadV2",
    "PinnedCurrentNaturalGenerationContentVerifierV2",
    "AuthorityV2NaturalGenerationContentService",
)
