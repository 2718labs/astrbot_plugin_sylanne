"""Synchronous installed bridge to the current double-paid review reader."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_natural_paid_review_contract import (
    NaturalPaidReviewCurrentReadRequestV2, NaturalPaidReviewCurrentReadV2,
)
from .natural_generation_output_port import InstalledNaturalGenerationOutputPortV2


class InstalledNaturalPaidReviewPortV2(InstalledNaturalGenerationOutputPortV2):
    def read_current_natural_paid_review_v2(
        self, request: NaturalPaidReviewCurrentReadRequestV2, *, now_utc: float,
    ) -> NaturalPaidReviewCurrentReadV2 | None:
        if type(request) is not NaturalPaidReviewCurrentReadRequestV2:
            raise TypeError("typed natural paid review request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("natural paid review must run on graph worker")
        future = asyncio.run_coroutine_threadsafe(
            self._client.natural_paid_review_current_read_v2(
                self._bundle, self._grant, read_request=request), self._loop)
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            # The original paid model calls are already terminal. A lost read
            # response needs a new bounded current-read attempt, never a retry
            # of either provider call.
            raise RuntimeError("natural paid review read timed out; new attempt required") from exc


__all__ = ("InstalledNaturalPaidReviewPortV2",)
