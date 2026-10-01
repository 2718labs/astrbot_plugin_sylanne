"""Compare installation identity while preserving each TLS session's own binding."""

from __future__ import annotations

from ..runtime_contracts import InstallationGrantV2


def same_installed_grant_identity_v2(
    graph_grant: InstallationGrantV2,
    client_grant: InstallationGrantV2,
) -> bool:
    if (type(graph_grant) is not InstallationGrantV2
            or type(client_grant) is not InstallationGrantV2):
        return False
    fields = (
        "authority_id", "subject", "administrator_holder", "installation_id",
        "manifest_digest", "publisher_policy_ref", "service_capability_version",
        "schema",
    )
    return all(getattr(graph_grant, field) == getattr(client_grant, field)
               for field in fields)


__all__ = ("same_installed_grant_identity_v2",)
