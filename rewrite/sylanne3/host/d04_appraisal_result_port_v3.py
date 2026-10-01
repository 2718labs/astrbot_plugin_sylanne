"""Credential-owning D04 result read bridge for the sole Graph worker."""
from __future__ import annotations
import asyncio
from .model_terminal_cost_port import InstalledModelTerminalCostPort


class InstalledD04AppraisalResultPortV3(InstalledModelTerminalCostPort):
    def read(self, request):
        if not self._loop.is_running():
            raise RuntimeError("installed D04 event loop unavailable")
        try:
            if asyncio.get_running_loop() is self._loop:
                raise RuntimeError("D04 result reader must run on Graph worker")
        except RuntimeError as exc:
            if str(exc) != "no running event loop":
                raise
        return asyncio.run_coroutine_threadsafe(self._client.d04_appraisal_result_read_v3(
            self._bundle, self._grant, read_request=request), self._loop).result(self._timeout)

    def recover_finish(self, request):
        return asyncio.run_coroutine_threadsafe(self._client.d04_appraisal_result_recover_finish_v3(
            self._bundle, self._grant, read_request=request), self._loop).result(self._timeout)
