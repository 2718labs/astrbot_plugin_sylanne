"""Independent current graph preflight for a sealed context-reply preparation.

This read proves neither a paid provider terminal nor permission to release its
body. A future result service must pair it with the original Authority intent,
terminal receipt, Owner read fence, D13 consumption barrier and D09 admission.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3

from ..graph_types import AtomKey, GraphVersion
from ..graph_store import GraphStore
from ..memory_types import SourceRecord
from ..runtime.context_reply_job_v2 import (
    ContextReplyJobHold, read_original_context_reply_call_binding_v2,
    read_original_context_reply_preparation_v2,
)
from ..runtime.d11_types import runtime_cost_settlement_key
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.c02_bundle_codec import c02_bundle_from_wire
from ..runtime_contracts import (
    ContextReplyOriginalSealV2, NamespaceId, QueryEpoch,
    canonical_digest, canonical_serialize, context_reply_graph_guard_digest_v2,
)
from .current_context_reply_source_verifier import (
    read_current_context_reply_sources_v1,
)
from .current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from .v2_context_reply_result_contract import ContextReplyResultReadRequestV1
from .v2_model_egress_contract import ModelEgressIntentV1
from .v2_model_egress_contract import ModelTerminalReceiptV2


@dataclass(frozen=True, slots=True)
class ContextReplyOriginalCurrentReadV2:
    """Content-free original/current match; deliberately remains HOLD."""

    seal: ContextReplyOriginalSealV2
    current_read_versions: tuple[GraphVersion, ...]
    current_guard_digest: str
    frozen_input_digest: str
    status: str = "original_preparation_current_hold"


@dataclass(frozen=True, slots=True)
class ContextReplyPaidCallCurrentReadV2:
    original: ContextReplyOriginalCurrentReadV2
    frozen_request: object
    model_call_request_digest: str
    worker_fence: int
    status: str = "paid_binding_current_hold"


class PinnedCurrentContextReplyOriginalVerifier:
    """Reopen the original row and reconstruct D07/D06 under one SQLite read."""

    def __init__(self, graph_db_path: str | Path):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("graph database path must be administrator-pinned and absolute")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")

    def current(self, request: ContextReplyResultReadRequestV1, *,
                now_utc: float) -> ContextReplyOriginalCurrentReadV2 | None:
        if type(request) is not ContextReplyResultReadRequestV1:
            return None
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._read(db, request, now_utc=now_utc)
                finally:
                    db.execute("ROLLBACK")
        except (ContextReplyJobHold, sqlite3.Error, KeyError, TypeError,
                ValueError, AttributeError, OverflowError):
            return None

    def paid_call_current(self, request: ContextReplyResultReadRequestV1,
                          intent: ModelEgressIntentV1,
                          terminal_receipt: ModelTerminalReceiptV2, *, now_utc: float
                          ) -> ContextReplyPaidCallCurrentReadV2 | None:
        """Read original paid call binding and current graph; still no body."""
        if (type(request) is not ContextReplyResultReadRequestV1
                or type(intent) is not ModelEgressIntentV1
                or type(terminal_receipt) is not ModelTerminalReceiptV2):
            return None
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    original = self._read(db, request, now_utc=now_utc)
                    if original is None:
                        return None
                    saved = read_original_context_reply_preparation_v2(
                        db, request.namespace, request.c02_operation_id,
                        request.source_ref)
                    c02_rows = db.execute(
                        "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        request.namespace.as_tuple + (request.c02_operation_id,),
                    ).fetchall()
                    if (len(c02_rows) != 1
                            or c02_bundle_from_wire(c02_rows[0][0]).envelope
                               .source_qualification.source_refs !=
                               (request.source_ref,)):
                        return None
                    binding = read_original_context_reply_call_binding_v2(db, saved)
                    if binding is None:
                        return None
                    seal = saved.seal
                    frozen = saved.frozen_request
                    cost_id = original_model_cost_operation_id_v1(
                        request.namespace, seal.call_id)
                    cost_rows = db.execute(
                        "SELECT activity_id,commit_seq,receipt_json FROM "
                        "graph_bundle_operations "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        request.namespace.as_tuple + (cost_id,),
                    ).fetchall()
                    if len(cost_rows) != 1:
                        return None
                    activity_id, commit_seq, receipt_json = cost_rows[0]
                    cost = json.loads(receipt_json)
                    committed = OriginalModelCostCommitV1(
                        **cost["original_model_cost"])
                    terminal = db.execute(
                        "SELECT terminal_receipt_digest,state FROM "
                        "graph_context_reply_terminals_v2 WHERE bot=? "
                        "AND persona=? AND original_operation_id=?",
                        request.namespace.as_tuple +
                        (seal.original_operation_id,),
                    ).fetchone()
                    event = db.execute(
                        "SELECT revisions,epoch_revision FROM graph_events "
                        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
                        request.namespace.as_tuple + (activity_id, cost_id),
                    ).fetchone()
                    cost_atom = db.execute(
                        "SELECT revision,value,valid,type_name FROM graph_atoms "
                        "WHERE token=? AND bot=? AND persona=?",
                        (committed.cost_ref, *request.namespace.as_tuple),
                    ).fetchone()
                    budget = db.execute(
                        "SELECT receipt_json FROM runtime_budget_operations "
                        "WHERE bot_id=? AND persona_id=? AND operation_id=? "
                        "AND phase='settle'",
                        request.namespace.as_tuple +
                        (seal.original_operation_id,),
                    ).fetchone()
                    reservation = db.execute(
                        "SELECT digest,state FROM runtime_budget_reservations "
                        "WHERE lease_id=? AND operation_id=?",
                        (intent.budget_lease_id,
                         seal.original_operation_id),
                    ).fetchone()
                    cost_value = (json.loads(cost_atom[1])
                                  if cost_atom is not None else None)
                    expected_terminal_digest = canonical_digest(
                        asdict(terminal_receipt))
                    if (canonical_serialize(cost) != receipt_json
                            or cost["original_model_cost"] != asdict(committed)
                            or cost.get("original_intent_digest") !=
                               canonical_digest(asdict(intent))
                            or cost.get("terminal_receipt_digest") !=
                               expected_terminal_digest
                            or (committed.status, committed.call_id,
                                committed.operation_id,
                                committed.terminal_receipt_digest,
                                committed.commit_seq, committed.quote_id,
                                committed.quote_version) !=
                               ("committed", seal.call_id, cost_id,
                                expected_terminal_digest, commit_seq,
                                "context-reply-quote:" + seal.job_id.split(":")[-1],
                                1)
                            or terminal != (expected_terminal_digest,
                                            "committed")
                            or event is None
                            or event[1] != committed.graph_epoch
                            or not any(
                                version.key.token == committed.cost_ref
                                and cost_atom is not None
                                and version.revision == cost_atom[0]
                                for version in GraphStore._version_rows(event[0]))
                            or cost_atom is None
                            or cost_atom[2:] != (1, "runtime.cost_settlement")
                            or committed.cost_ref !=
                               runtime_cost_settlement_key(
                                   *request.namespace.as_tuple,
                                   activity_id, cost_id).token
                            or budget is None
                            or canonical_digest(json.loads(budget[0])) !=
                               committed.budget_receipt_digest
                            or reservation != (
                                intent.budget_reservation_digest, "settled")
                            or type(cost_value) is not dict
                            or cost_value.get("bundle_operation_id") != cost_id
                            or cost_value.get("settlement_id") != cost_id
                            or cost_value.get("cost_operation_id") !=
                               seal.original_operation_id
                            or cost_value.get("budget_operation_id") !=
                               seal.original_operation_id
                            or cost_value.get("budget_phase") != "settle"
                            or cost_value.get("lease_id") !=
                               intent.budget_lease_id
                            or cost_value.get("activity_id") != activity_id
                            or cost_value.get("effect_id") is not None
                            or cost_value.get("budget_receipt_digest") !=
                               hashlib.sha256(budget[0].encode("utf-8")).hexdigest()):
                        return None
                    if (saved.state != "terminal"
                            or (intent.authority_id, intent.namespace,
                                intent.job_id, intent.operation_id, intent.call_id,
                                intent.request_digest, intent.worker_fence,
                                intent.provider_id, intent.model_id,
                                intent.provider_config_digest,
                                intent.max_output_tokens,
                                intent.access_epoch, intent.delete_epoch,
                                intent.authority_activation_generation,
                                intent.budget_reservation_operation_id) !=
                               (request.authority_id, request.authority_namespace,
                                seal.job_id, seal.acquire_operation_id, seal.call_id,
                                binding.model_call_request_digest,
                                binding.worker_fence,
                                frozen.installation.provider_id,
                                frozen.installation.model_id,
                                frozen.installation.provider_config_digest,
                                frozen.installation.max_output_tokens,
                                frozen.input.access_epoch, frozen.input.delete_epoch,
                                frozen.input.activation_generation,
                                seal.original_operation_id)
                            or intent.acquire_operation_id != seal.acquire_operation_id
                            or tuple(intent.source_refs) != tuple(
                                AtomKey.from_token(part.ref.ref).owner.subject
                                for part in frozen.input.evidence)
                            or intent.source_revisions != tuple(
                                (AtomKey.from_token(part.ref.ref).owner.subject,
                                 part.ref.version)
                                for part in frozen.input.evidence)
                            or intent.access_revisions != tuple(
                                (AtomKey.from_token(part.ref.ref).owner.subject,
                                 part.access_ref.version)
                                for part in frozen.input.evidence)):
                        return None
                    return ContextReplyPaidCallCurrentReadV2(
                        original, frozen, binding.model_call_request_digest,
                        binding.worker_fence)
                finally:
                    db.execute("ROLLBACK")
        except (ContextReplyJobHold, sqlite3.Error, KeyError, TypeError,
                ValueError, AttributeError, OverflowError):
            return None

    @staticmethod
    def _read(db: sqlite3.Connection, request: ContextReplyResultReadRequestV1,
              *, now_utc: float) -> ContextReplyOriginalCurrentReadV2 | None:
        namespace = request.namespace
        saved = read_original_context_reply_preparation_v2(
            db, namespace, request.c02_operation_id, request.source_ref)
        if saved is None:
            return None
        seal = saved.seal
        input = saved.frozen_request.input
        original_source_id = AtomKey.from_token(request.source_ref).owner.subject
        ingress_rows = db.execute(
            "SELECT conversation_ref FROM graph_first_ingress_identity_v1 "
            "WHERE bot=? AND persona=? AND source_ref=?",
            namespace.as_tuple + (original_source_id,),
        ).fetchall()
        if ((seal.installation_id, seal.job_id, seal.original_operation_id,
             seal.acquire_operation_id, seal.call_id, seal.model_request_digest,
             seal.frozen_input_digest, seal.template_version) !=
            (request.installation_id, request.job_id, request.original_operation_id,
             request.acquire_operation_id, request.call_id,
             request.model_request_digest, request.frozen_input_digest,
             request.template_version)
                or saved.state not in {"queued", "acquired", "terminal"}
                or saved.query_epoch != QueryEpoch(
                    namespace, input.scene_ref.ref, saved.graph_epoch)
                or len(ingress_rows) != 1
                or ingress_rows[0][0] != input.conversation_ref
                or input.conversation_ref != input.audience_ref.ref):
            return None
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone()
        if epoch is None or type(epoch[0]) is not int:
            return None
        snapshot, attention = PinnedCurrentModelEgressGraphVerifier._reply_snapshot(
            db, namespace, request.source_ref, epoch[0], now_utc)
        roots = {part.ref.ref for part in input.evidence}
        if (roots != set(attention.ticket.source_refs)
                or request.source_ref not in roots
                or set(snapshot.versions) != set(saved.read_versions)):
            return None
        original = snapshot.get(AtomKey.from_token(request.source_ref))
        if (original is None or not original.valid
                or input.question.text != SourceRecord.from_dict(original.value).text):
            return None
        sources = read_current_context_reply_sources_v1(
            db, saved.frozen_request, now_utc=now_utc)
        if (sources is None
                or not set(sources.read_versions) <= set(snapshot.versions)):
            return None
        current_query = QueryEpoch(namespace, input.scene_ref.ref, epoch[0])
        current_digest = context_reply_graph_guard_digest_v2(
            snapshot.versions, current_query, graph_epoch=epoch[0],
            access_epoch=input.access_epoch, delete_epoch=input.delete_epoch,
            activation_generation=input.activation_generation)
        original_digest = context_reply_graph_guard_digest_v2(
            saved.read_versions, saved.query_epoch,
            graph_epoch=saved.graph_epoch, access_epoch=saved.access_epoch,
            delete_epoch=saved.delete_epoch,
            activation_generation=input.activation_generation)
        if original_digest != seal.graph_guard_digest:
            return None
        return ContextReplyOriginalCurrentReadV2(
            seal, snapshot.versions, current_digest, seal.frozen_input_digest)


__all__ = [
    "ContextReplyOriginalCurrentReadV2",
    "ContextReplyPaidCallCurrentReadV2",
    "PinnedCurrentContextReplyOriginalVerifier",
]
