"""An old Authority backup cannot describe a used namespace as unbound."""

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.runtime_contracts import NamespaceId, NamespaceRuntimeState


def test_missing_authority_row_with_newer_deletion_history_is_quarantined(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        deletion.append_intent(
            namespace="ns-a", operation_id="erase-a",
            closure_roots=("source-a",), epoch=1, policy_ref="policy-a")
        # An older Authority backup can lack the namespace registration while
        # its independent deletion journal still records an irreversible intent.
        core._db.execute("DELETE FROM authority_namespaces WHERE namespace='ns-a'")

        bootstrap = service.namespace_bootstrap(
            credential="ok", subject="subject-a",
            namespace_id=NamespaceId("bot", "persona"))
        assert bootstrap.state is NamespaceRuntimeState.QUARANTINED
        assert bootstrap.anchor is None
        assert "orphaned_journal_history" in bootstrap.blocking_reasons
        with pytest.raises(AuthorityUnavailable):
            service.activate_namespace(
                credential="ok", subject="subject-a", holder="holder-a",
                namespace_id=NamespaceId("bot", "persona"), request_id="retry-a")
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
