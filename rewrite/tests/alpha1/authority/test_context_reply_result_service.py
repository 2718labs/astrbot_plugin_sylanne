"""An original V2 preparation alone cannot release paid content."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_context_reply_original_verifier import (
    _prepared_graph,
)
from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.current_context_reply_original_verifier import (
    PinnedCurrentContextReplyOriginalVerifier,
)
from sylanne3.authority_service.v2_context_reply_result_service import (
    AuthorityV2ContextReplyResultReadService,
)
from sylanne3.authority_service.v2_model_egress_store import (
    AuthorityV2ModelEgressStore,
)


def test_queued_original_without_paid_terminal_never_opens_result_fence(tmp_path):
    path = tmp_path / "graph.sqlite"
    request = _prepared_graph(path)
    fences, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        anchor = fences.current_anchor(credential="ok", subject="worker-a")
        request = replace(request, authority_id=anchor.authority_id,
                          authority_namespace="ns-a")
        service = AuthorityV2ContextReplyResultReadService(
            store=AuthorityV2ModelEgressStore(
                core._db, create=True, lock=core._lock),
            fences=fences,
            graph_verifier=PinnedCurrentContextReplyOriginalVerifier(path),
            installation_id=request.installation_id,
            read_subject="worker-a", holder="holder-a",
            trusted_now_utc=lambda: 10.0)
        with pytest.raises(AuthorityUnavailable, match="terminal unavailable"):
            service.prepare(credential="ok", request=request, now_utc=10.0)
        assert fences.fences._row(core._db, request.read_attempt_id) is None
        # A lost transport can close its original read attempt by identity
        # without ever returning a body, even when current content is gone.
        fences.begin_fence(
            credential="ok", subject="worker-a", holder="holder-a",
            operation="read", operation_id=request.read_attempt_id,
            expected_anchor=anchor)
        service.recover_finish(credential="ok", request=request)
        assert fences.fences._row(core._db, request.read_attempt_id)[6] == "finished"
        service.recover_finish(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
