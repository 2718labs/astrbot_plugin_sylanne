"""Installed mTLS accounting fence bridge for the dedicated graph worker."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledAccountingMaintenancePort:
    def __init__(
        self, *, client: AuthorityClient, bundle: AdminInstallationBundle,
        grant: InstallationGrantV2, owner_loop: asyncio.AbstractEventLoop,
    ) -> None:
        if (type(client) is not AuthorityClient
                or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or not isinstance(owner_loop, asyncio.AbstractEventLoop)
                or not owner_loop.is_running()
                or (grant.authority_id, grant.installation_id,
                    grant.administrator_holder, grant.manifest_digest) !=
                   (bundle.installation_policy.expected_authority_id,
                    bundle.installation_policy.installation_id,
                    bundle.installation_policy.administrator_holder,
                    bundle.installation_policy.manifest_digest)):
            raise ValueError("installed accounting observer binding required")
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def _call(self, method: str, request: AccountingMaintenanceRequestV1,
              grant: AccountingMaintenanceGrantV1 | None = None):
        if type(request) is not AccountingMaintenanceRequestV1:
            raise TypeError("original accounting request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("accounting fence must run on the graph worker")
        kwargs = {"accounting_request": request}
        if grant is not None:
            if type(grant) is not AccountingMaintenanceGrantV1:
                raise TypeError("original accounting grant required")
            kwargs["accounting_grant"] = grant
        future = asyncio.run_coroutine_threadsafe(
            getattr(self._client, method)(self._bundle, self._grant, **kwargs),
            self._loop)
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("original accounting fence outcome unresolved") from exc

    def begin(self, request: AccountingMaintenanceRequestV1):
        return self._call("accounting_begin_v1", request)

    def validate(self, request: AccountingMaintenanceRequestV1,
                 grant: AccountingMaintenanceGrantV1):
        return self._call("accounting_validate_v1", request, grant)

    def finish(self, request: AccountingMaintenanceRequestV1,
               grant: AccountingMaintenanceGrantV1):
        return self._call("accounting_finish_v1", request, grant)

    def recover_finish(self, request: AccountingMaintenanceRequestV1):
        return self._call("accounting_recover_finish_v1", request)


__all__ = ("InstalledAccountingMaintenancePort",)
