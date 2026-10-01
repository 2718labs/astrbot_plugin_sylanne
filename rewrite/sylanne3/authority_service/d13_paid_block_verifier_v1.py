"""Current consumption of a D13 block from its real settled paid original.

W01 reopens its immutable authenticated result read and signed cost originals.
Authority additionally joins those bytes to its independently owned model
ledger. Neither path calls a provider or repurposes the D09 review verifier.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import sqlite3

from ..graph_types import AtomKey, Owner
from ..model_broker.d13_precompression import (
    D13PrecompressionInstallationV1, freeze_d13_precompression_request_v1,
    issue_unadmitted_d13_model_request_v1, parse_d13_precompression_output_v1,
)
from ..runtime_contracts import canonical_digest


class InstalledD13PaidBlockVerifierV1:
    def __init__(self, db, *, installation, resource_issuer, budget_issuer,
                 authority_store=None, max_slots=64):
        from ..runtime.issuers import D02ResourceIssuer, D11BudgetGrantIssuer
        from .v2_model_egress_store import AuthorityV2ModelEgressStore
        if (type(db) is not sqlite3.Connection
                or type(installation) is not D13PrecompressionInstallationV1
                or type(resource_issuer) is not D02ResourceIssuer
                or not isinstance(budget_issuer, D11BudgetGrantIssuer)
                or authority_store is not None and type(authority_store) is not AuthorityV2ModelEgressStore
                or type(max_slots) is not int or not 1 <= max_slots <= 64):
            raise ValueError("installed D13 paid original authorities required")
        self._db, self._installation = db, installation
        self._resource, self._budget = resource_issuer, budget_issuer
        self._authority, self._max_slots = authority_store, max_slots

    def verify_current_paid_model_block_v2(self, candidate, *, plan, window):
        try:
            return self._verify(candidate, plan, window)
        except Exception:
            return False

    def _verify(self, candidate, plan, window):
        from ..domains.d13.precompression import compile_extractive_model_output, EXTRACTIVE_MODEL_VERSION
        from ..domains.d13.provider import _block_from_graph_value, retirement_reason
        from ..runtime.d13_current_window import read_current_d13_window_for_authority_v1
        from ..runtime.d13_paid_intent_original_v1 import (
            load_d13_paid_intent_original_v1, read_d13_paid_call_original_v1, PAID_WORK_KIND,
        )
        from ..runtime.d13_paid_coordinator_v1 import (
            read_paid_d13_evidence_in_transaction_v1, read_paid_d13_settlement_in_transaction_v1,
        )
        from ..runtime.jobs import get_job
        from ..runtime.d11_types import job_graph_write
        from .v2_worker_model_result_contract import d13_paid_read_attempt_id_v1
        db = self._db
        if not db.in_transaction or candidate.compiler_version != EXTRACTIVE_MODEL_VERSION or candidate.status != "candidate":
            return False
        scene_id = AtomKey.from_token(window.scene_ref.ref).owner.subject
        current = read_current_d13_window_for_authority_v1(db, window.namespace, scene_id,
            window.conversation_ref, self._max_slots, window.trusted_utc,
            expected_activation_generation=window.activation_epoch)
        if current != window or retirement_reason(replace(candidate, status="standby"), plan, window) is not None:
            return False
        loaded = load_d13_paid_intent_original_v1(db, window.namespace, plan.job_ref)
        if loaded is None:
            return False
        original, frozen = loaded
        if (frozen.plan != plan or frozen.installation != self._installation
                or window.trusted_utc < frozen.window.trusted_utc
                or window.trusted_utc >= original.binding.expires_at_utc
                or freeze_d13_precompression_request_v1(window, plan, self._installation).turns != frozen.turns):
            return False
        saved_call = read_d13_paid_call_original_v1(db, window.namespace, plan.job_ref)
        if saved_call is None:
            return False
        call, request = saved_call
        if (call.binding_digest != original.binding.binding_digest
                or call.intent_original_digest != original.original_digest
                or request != issue_unadmitted_d13_model_request_v1(request.envelope, frozen,
                    call_id=original.binding.call_id, timeout_seconds=request.timeout_seconds,
                    privacy_tier=request.privacy_tier)):
            return False
        evidence = read_paid_d13_evidence_in_transaction_v1(db, original, call)
        if evidence is None:
            return False
        settlement = read_paid_d13_settlement_in_transaction_v1(db, original, evidence)
        if settlement is None or settlement.receipt.status != "settled":
            return False
        read, fact = evidence.read, evidence.fact
        intent, binding = fact.intent, original.binding
        read.require_original_intent(intent)
        from .d13_source_identity_v1 import d13_original_source_identity_v1
        source_ids, source_revisions, access_revisions = d13_original_source_identity_v1(frozen)
        if (intent.source_refs != source_ids or intent.source_revisions != source_revisions
                or intent.access_revisions != access_revisions
                or read.request.purpose != "d13_precompress_paid"
                or read.request.namespace != window.namespace
                or read.request.binding_digest != binding.binding_digest
                or read.request.installation_id != self._installation.installation_id
                or read.request.consumer_operation_id != "d13-adopt:" + binding.binding_digest
                or not any(read.request.read_attempt_id == d13_paid_read_attempt_id_v1(
                    read.request.consumer_operation_id, n) for n in range(1, 65))
                or intent.binding_digest != binding.binding_digest
                or intent.request_digest != call.request_digest
                or intent.call_id != binding.call_id or intent.job_id != binding.job_ref
                or intent.operation_id != binding.original_operation_id
                or intent.acquire_operation_id != binding.original_operation_id
                or intent.budget_reservation_operation_id != original.budget_operation_id
                or intent.budget_reservation_digest != original.budget_reservation_digest
                or dict(intent.budget_ceiling) != original.ceiling
                or intent.worker_fence != call.worker_fence
                or (intent.provider_id, intent.model_id, intent.provider_config_digest,
                    intent.max_output_tokens) != (self._installation.provider_id,
                    self._installation.model_id, self._installation.provider_config_digest,
                    self._installation.max_output_tokens)
                or fact.recovery.state != "observed" or fact.recovery.content_erased
                or read.terminal_receipt != fact.receipt
                or fact.receipt.finish_digest != "sha256:" + read.observation.digest):
            return False
        job = get_job(db, plan.job_ref)
        if (job.work_kind != PAID_WORK_KIND or job.phase != "completed" or job.cancel_epoch != 0
                or (job.bot_id, job.persona_id) != window.namespace.as_tuple
                or job.fence != call.worker_fence or job.result_ref != candidate.block_ref
                or job.operation_id != binding.original_operation_id or job.budget_ref != intent.budget_lease_id
                or job.continuation.get("binding_digest") != binding.binding_digest):
            return False
        job_write = job_graph_write(job)
        job_row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_write.key.token,)).fetchone()
        if job_row is None or job_row[1] != 1 or json.loads(job_row[0]) != job_write.value:
            return False
        quote = self._resource.original_signed_quote(db, original.quote_id, original.quote_version)
        grant, _signature = self._budget.signed_budget_grant_at_version(db, job.budget_ref, original.grant_version)
        reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?", (job.budget_ref, original.budget_operation_id)).fetchone()
        receipt = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND phase='settle'", window.namespace.as_tuple + (original.budget_operation_id,)).fetchone()
        if (canonical_digest(quote) != original.quote_digest or canonical_digest(grant) != original.grant_digest
                or quote.work_kind != PAID_WORK_KIND or quote.operation_id != original.budget_operation_id
                or quote.parent_budget_lease_ref != job.budget_ref or dict(quote.ceiling) != original.ceiling
                or grant.grant_id != original.grant_id or PAID_WORK_KIND not in grant.allowed_work_kinds
                or (quote.bot_id, quote.persona_id) != window.namespace.as_tuple
                or (grant.bot_id, grant.persona_id) != window.namespace.as_tuple
                or reservation is None or reservation[0] != original.budget_reservation_digest
                or json.loads(reservation[1]) != original.ceiling or reservation[2] != "settled"
                or receipt is None or json.loads(receipt[0]) != asdict(settlement.receipt)):
            return False
        key = AtomKey(Owner("persona", *window.namespace.as_tuple), "d13.compressed_turn_block.v2", candidate.block_ref)
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (row is None or row[1] != 1 or db.execute("SELECT 1 FROM graph_d13_retirements_v1 "
                "WHERE bot=? AND persona=? AND block_token=?", window.namespace.as_tuple + (key.token,)).fetchone()):
            return False
        stored = _block_from_graph_value(json.loads(row[0]))
        if stored.status not in {"standby", "active"} or replace(stored, status="candidate") != candidate:
            return False
        result = json.loads(read.observation.result_json)
        if type(result) is not dict or set(result) != {"text"} or type(result["text"]) is not str:
            return False
        parsed = parse_d13_precompression_output_v1(result["text"], frozen)
        if compile_extractive_model_output(window, plan, parsed.model_text) != candidate:
            return False
        if self._authority is not None:
            # Authority owns this store and lock; W01 never supplies a "verified"
            # boolean. Holding only its read lock here performs no RPC or writes.
            store = self._authority
            with store._lock:
                opened = not store._db.in_transaction
                if opened:
                    store._db.execute("BEGIN")
                try:
                    recovery = store._read(store._db, binding.call_id)
                    if recovery is None or recovery != fact.recovery or recovery.intent != intent:
                        return False
                    admission, report_digest, terminal = store.read_admission_locked(store._db, intent)
                    from .v2_fence_store import AuthorityV2FenceStore
                    fence_row = AuthorityV2FenceStore._row(store._db, intent.operation_id)
                    if fence_row is None or fence_row[6] != "finished" or fence_row[10] is not None:
                        return False
                    permit = AuthorityV2FenceStore._permit(fence_row)
                    if (permit.operation != "model_egress"
                            or (permit.authority_id, permit.namespace, permit.subject,
                                permit.operation_id, permit.token, permit.fence_epoch, permit.revision,
                                permit.generation, canonical_digest(asdict(permit.pinned_anchor))) !=
                               (intent.authority_id, intent.namespace, intent.subject, intent.operation_id,
                                intent.fence_token, intent.fence_epoch, intent.fence_revision,
                                intent.authority_activation_generation, intent.anchor_digest)
                            or fence_row[8:10] != (intent.call_id, fact.receipt.finish_digest)):
                        return False
                    if (admission != fact.admission or terminal != fact.receipt
                            or report_digest != terminal.report_digest
                            or not store.is_fence_bound_locked(store._db, intent)
                            or store._read_observation_locked(store._db, intent) != read.observation):
                        return False
                finally:
                    if opened:
                        store._db.execute("ROLLBACK")
        return True


def build_installed_d13_paid_block_verifier_v1(db, *, installation,
        resource_issuer, budget_issuer, authority_store=None, max_slots=64):
    if installation is None:
        return None
    return InstalledD13PaidBlockVerifierV1(db, installation=installation,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer,
        authority_store=authority_store, max_slots=max_slots)
