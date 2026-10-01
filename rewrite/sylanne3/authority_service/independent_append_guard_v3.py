"""Concrete journal-first critical section for installed execution originals.

Graph/current-input reads must be completed under an actual durable exclusive
permit before entry. No Graph callback or RPC belongs in this critical section.
The caller opens a short journal.freeze_writes transaction, performs its final
Core/live-permit checks and trusted append, exits that journal transaction to
commit it, then opens a read-only journal guard to reconcile/consume in the
still-held Core transaction. Only afterward can Core commit its new head.
"""
from contextlib import contextmanager
from .contract import AuthorityUnavailable


@contextmanager
def independent_append_core_guard_v3(bridge):
    from .v2_execution_bridge import AuthorityV2ExecutionBridge
    if type(bridge) is not AuthorityV2ExecutionBridge:
        raise AuthorityUnavailable("actual same-Core execution bridge required")
    # Logical writer lock order remains deletion -> execution -> Core. The
    # journal's SQL transaction is deliberately *inside* Core's SQL lifetime,
    # so its append commits first while Core revocation/admission stays excluded.
    with bridge.deletion.freeze_writes():
        deletion_head=bridge.deletion.verified_head()
        with bridge.journal._lock:
            if bridge.journal._db is None or bridge.journal._db.in_transaction:
                raise AuthorityUnavailable("independent append needs a fresh journal transaction")
            with bridge.core._tx() as db:
                yield db,deletion_head
                if bridge.journal._db.in_transaction:
                    raise AuthorityUnavailable("journal append must commit before Core can advertise its head")
