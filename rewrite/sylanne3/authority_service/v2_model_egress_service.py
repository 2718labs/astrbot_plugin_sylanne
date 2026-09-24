"""HOLD-only model egress service until current graph and executor integration."""

from __future__ import annotations

from .contract import AuthorityUnavailable
from .v2_model_egress_store import AuthorityV2ModelEgressStore


class AuthorityV2ModelEgressService:
    def __init__(self, store: AuthorityV2ModelEgressStore):
        if type(store) is not AuthorityV2ModelEgressStore:
            raise TypeError("Authority-owned model egress store required")
        self._store = store

    async def begin_handoff(self, request, request_digest):
        raise AuthorityUnavailable(
            "HOLD: independent current graph verifier and fenced executor are not integrated"
        )

    async def finish_handoff(self, start, outcome_digest):
        raise AuthorityUnavailable(
            "HOLD: independent provider observation and fenced finish are not integrated"
        )


__all__ = ["AuthorityV2ModelEgressService"]
