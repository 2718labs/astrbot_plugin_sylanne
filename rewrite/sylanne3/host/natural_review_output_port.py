"""Synchronous installed bridge to the original paid review selector."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_natural_review_output_contract import (
    NaturalReviewOriginalOutputV2, NaturalReviewOutputReadRequestV2,
)
from .natural_generation_output_port import InstalledNaturalGenerationOutputPortV2


class InstalledNaturalReviewOutputPortV2(InstalledNaturalGenerationOutputPortV2):
    def read_original_natural_review_output_v2(
        self, request: NaturalReviewOutputReadRequestV2, *, now_utc: float,
    ) -> NaturalReviewOriginalOutputV2 | None:
        if type(request) is not NaturalReviewOutputReadRequestV2:
            raise TypeError("typed natural review output request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("natural review read must run on the graph worker")
        future = asyncio.run_coroutine_threadsafe(
            self._client.natural_review_output_select_v2(
                self._bundle, self._grant, read_request=request), self._loop)
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            recovery = asyncio.run_coroutine_threadsafe(
                self._client.natural_review_output_recover_finish_v2(
                    self._bundle, self._grant, read_request=request), self._loop)
            try:
                recovery.result(self._timeout)
            except Exception as recovery_exc:
                raise RuntimeError(
                    "natural review read unresolved; original fence recovery required"
                ) from recovery_exc
            raise RuntimeError("natural review read timed out") from exc


__all__ = ("InstalledNaturalReviewOutputPortV2",)
