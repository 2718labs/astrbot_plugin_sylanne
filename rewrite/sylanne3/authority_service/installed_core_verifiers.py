"""Installed Core callbacks backed by the reopened independent v2 journals.

Core's legacy advance/effect/dispatch routes are sealed in a v2-only service.
These callbacks verify installer genesis and exact current heads only. A legacy
advance needs a public, writer-frozen prefix proof from each journal; until
that exists it is deliberately unavailable.
"""

from __future__ import annotations

from typing import Mapping

from .contract import AuthorityUnavailable, JournalHead
from .deployment_config import AuthorityCoreVerifiers
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal


def installed_core_verifier_factory(
    deletion: AuthorityV2DeletionGuard,
    execution: Mapping[str, AuthorityV2ExecutionJournal],
) -> AuthorityCoreVerifiers:
    """Build fail-closed callbacks from already-opened installer-owned logs.

    Legacy register/seal takes Core's lock before these journal writer locks.
    Installers must perform that bootstrap while the service is stopped under
    its exclusive maintenance lock. Once sealed v2-only, Core's legacy
    transaction gate rejects those routes before any callback is invoked.
    """
    if type(deletion) is not AuthorityV2DeletionGuard or not execution:
        raise AuthorityUnavailable("installed independent journals are required")
    journals = dict(execution)
    if any(type(namespace) is not str or not namespace
           or type(journal) is not AuthorityV2ExecutionJournal
           or journal.namespace != namespace
           for namespace, journal in journals.items()):
        raise AuthorityUnavailable("installed execution namespace binding differs")

    def supported(previous: JournalHead | None, current: JournalHead) -> bool:
        return (type(current) is JournalHead
                and (previous is None or previous == current))

    def deletion_check(namespace, previous, current, phase) -> bool:
        if namespace not in journals or not supported(previous, current):
            return False
        if phase not in ("clear", "pending", "accepted"):
            return False
        with deletion.freeze_writes():
            if deletion.verified_head() != current:
                return False
            phases = (operation_phase for (operation_namespace, _), operation_phase
                      in deletion.latest_phases().items()
                      if operation_namespace == namespace)
            current_phases = set(phases)
            actual = ("pending" if "pending" in current_phases else
                      "accepted" if "accepted" in current_phases else "clear")
            return actual == phase

    def execution_check(namespace, previous, current, phase) -> bool:
        journal = journals.get(namespace)
        if journal is None or phase is not None or not supported(previous, current):
            return False
        with journal.freeze_writes():
            return journal.verified_head() == current

    def denied_legacy_effect(*_args) -> bool:
        return False

    def denied_legacy_dispatch(*_args) -> bool:
        return False

    return AuthorityCoreVerifiers(
        deletion_check, execution_check, denied_legacy_effect,
        denied_legacy_dispatch)


__all__ = ["installed_core_verifier_factory"]
