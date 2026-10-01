"""Narrow authorization callbacks for a separately installed Authority.

The installer must protect the process, asset manifest, databases and TLS keys
with OS ACLs. This module cannot turn plugin-owned Python into a trust root.
Publisher enrollment remains unavailable until a signed formal package is
verified against an installer-owned publisher trust root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .contract import AuthorityUnavailable, CONTENT_OPERATIONS, identifier
from .mtls_server import MtlsPeerCredential


_PEER_ACTIONS = CONTENT_OPERATIONS | frozenset({
    "current", "anchor", "release", "deletion", "execution", "dispatch",
})
_LOCAL_ACTIONS = frozenset({
    "seal_v2_only", "install", "transfer", "revoke", "activate", "recover",
    "migration_begin", "migration_revoke", "migration_prepare_target",
    "migration_activate", "migration_recover", "owner_identity_pair",
    "owner_identity_revoke", "self_identity_mutate", "c04_execute",
})


@dataclass(frozen=True, slots=True)
class InstalledPeerScopeV1:
    namespace: str
    holder: str

    def __post_init__(self) -> None:
        identifier(self.namespace, "namespace")
        identifier(self.holder, "holder")


class _LocalAdministratorCredential:
    __slots__ = ("action", "namespace", "_issuer")

    def __init__(self, action: str, namespace: str, issuer: object) -> None:
        self.action = action
        self.namespace = namespace
        self._issuer = issuer


def _effective_windows_administrator() -> bool:
    # CheckTokenMembership uses the effective thread token, including UAC
    # filtering. It is deliberately rechecked at authorization time.
    from .admin_cli import AdminCliHold, _require_windows_administrator_token

    try:
        _require_windows_administrator_token()
    except AdminCliHold:
        return False
    return True


class InstalledAuthorityPolicyV1:
    """Pinned peer scopes plus an OS-gated, process-local administrator token.

    Construct this only from an ACL-protected installer configuration inside
    the independent Authority process. A caller-supplied mapping is not proof
    of installation. The peer certificate digest is trusted only after the
    TLS listener verifies possession of that certificate.
    """

    def __init__(self, peer_scopes: Mapping[str, InstalledPeerScopeV1]) -> None:
        if not peer_scopes:
            raise AuthorityUnavailable("installed peer scopes are absent")
        scopes = {}
        for digest, scope in peer_scopes.items():
            if (type(digest) is not str or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)
                    or type(scope) is not InstalledPeerScopeV1):
                raise AuthorityUnavailable("installed peer scope differs")
            scopes[digest] = scope
        self._peer_scopes = scopes
        self._issuer = object()

    def local_administrator_credential(self, action: str, namespace: str) -> object:
        identifier(namespace, "namespace")
        if action not in _LOCAL_ACTIONS or not _effective_windows_administrator():
            raise AuthorityUnavailable("effective local administrator is unavailable; HOLD")
        return _LocalAdministratorCredential(action, namespace, self._issuer)

    def core_authorizer(self, credential: object, action: str, namespace: str,
                        holder: str | None) -> bool:
        if type(credential) is _LocalAdministratorCredential:
            return (credential._issuer is self._issuer
                    and (credential.action == action or
                         (credential.action == "c04_execute" and
                          action in {"execution", "current"}))
                    and credential.namespace == namespace
                    and (action in _LOCAL_ACTIONS or
                         credential.action == "c04_execute")
                    and _effective_windows_administrator())
        if type(credential) is not MtlsPeerCredential or action not in _PEER_ACTIONS:
            return False
        scope = self._peer_scopes.get(credential.certificate_sha256)
        return (scope is not None and scope.namespace == namespace
                and (holder is None or holder == scope.holder))

    def administrator_authorizer(self, credential: object, action: str,
                                 namespace: str, holder: str | None) -> bool:
        # Remote enrollment is intentionally closed: a TLS client certificate
        # alone does not prove the OS administrator or formal publisher package.
        return self.core_authorizer(credential, action, namespace, holder)

    @staticmethod
    def publisher_manifest_verifier(profile_id: str, plugin_name: str,
                                    host_api_version: str,
                                    manifest_sha256: str) -> bool:
        # No formal signed package / publisher root is currently installed.
        return False


__all__ = ("InstalledAuthorityPolicyV1", "InstalledPeerScopeV1")
