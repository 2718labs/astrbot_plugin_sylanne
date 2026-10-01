"""The natural host driver uses the acquired original, never a new call ID."""

from dataclasses import replace

from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent
from rewrite.tests.alpha1.runtime.test_natural_reply_job_v2 import (
    _case, _generation_call,
)
from sylanne3.authority_service.natural_original_binding_verifier import (
    NaturalOriginalCallIdentityReadV2,
)
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressDraftV1
from sylanne3.host.installed_natural_reply_driver import _original_generation_binding
from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from sylanne3.runtime.restore_anchor import RestoreAnchor


def test_host_generation_joins_current_draft_to_original_call_and_fence():
    namespace, parent, seal, frozen, versions, queries, queued = _case()
    call = _generation_call(namespace, seal, frozen, versions, queries)
    saved = SavedNaturalPreparationV2(
        "generation", parent, seal, frozen, versions, queries,
        2, 3, 4, "queued", None, None, None, None)
    running = replace(
        queued, phase="running", lease_holder="worker",
        lease_expires_utc="2026-09-28T00:00:30Z", fence=1)
    original = NaturalOriginalCallIdentityReadV2(
        "generation", seal, call, call.digest, running.fence)
    draft = ModelEgressDraftV1.from_intent(intent(
        subject="worker", operation_id=seal.acquire_operation_id,
        call_id=seal.call_id, request_digest=call.digest,
        job_id=seal.job_id, worker_fence=running.fence,
        budget_lease_id=seal.parent_budget_lease_id,
        budget_reservation_operation_id=seal.reservation_operation_id,
        acquire_operation_id=seal.acquire_operation_id,
        binding_digest="b" * 64))
    anchor = RestoreAnchor(
        "authority", "bot:persona", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof")

    assert _original_generation_binding(
        saved, running, call, (call, draft, anchor), original) == (draft, anchor)
    assert _original_generation_binding(
        saved, running, call,
        (call, replace(draft, worker_fence=2), anchor), original) is None
    assert _original_generation_binding(
        saved, replace(running, fence=2), call,
        (call, draft, anchor), original) is None
    assert _original_generation_binding(
        saved, running, call, (call, draft, anchor),
        replace(original, typed_request_digest="0" * 64)) is None
