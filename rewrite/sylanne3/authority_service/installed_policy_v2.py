"""Explicitly pinned Linux/Windows installation policy for the alpha1 backend.

Unlike the diagnostic V1 policy, enrollment is available only for the exact
administrator-installed package, profile and mTLS certificate. It grants no
Owner identity; signed Owner sessions and domain admission remain independent.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .contract import AuthorityUnavailable, CONTENT_OPERATIONS, identifier
from .installed_policy import InstalledPeerScopeV1, _LocalAdministratorCredential, _effective_windows_administrator
from .mtls_server import MtlsPeerCredential
from ..host.installed_package import verify_installed_backend_runtime_v1

_PEER = CONTENT_OPERATIONS | frozenset({
    "current", "anchor", "release", "delete", "deletion", "execution", "accounting",
    "namespace_genesis", "owner_pair", "owner_claim", "owner_proof", "owner_session",
    "owner_session_revoke", "owner_guard_read", "owner_authorization_revoke", "self_identity_read",
    "migration_begin", "migration_revoke", "migration_prepare_target", "migration_activate",
    "migration_recover", "execution_redaction_install", "d12_operation_status",
    "d12_lifecycle_control", "d12_lifecycle_bootstrap",
    "d12_package_control", "d12_package_supervisor", "d12_package_bootstrap", "d12_package_activate",
})
_LOCAL = frozenset({
    "install", "seal_v2_only", "activate", "recover", "transfer", "revoke",
    "owner_identity_pair", "owner_identity_revoke", "self_identity_mutate",
    "migration_pair_install", "migration_pair_register", "migration_pair_revoke",
    "migrate_deletion", "erasure_closure_install", "execution_redaction_install",
    "c04_execute", "c09_maintenance", "d12_operation_install", "d12_target_install",
    "d12_target_register", "d12_target_owner_install", "d12_lifecycle_install",
    "d12_package_install",
})
_C09 = frozenset({"current", "read", "write", "delete", "deletion", "execution",
    "recover", "erasure_closure_install", "execution_redaction_install"})


class InstalledAuthorityPolicyV2:
    def __init__(self, *, peer_scopes, profile_peers, package_root,
                 trusted_manifest_sha256, authority_uid=0):
        root = Path(package_root)
        if not root.is_absolute() or root.is_symlink():
            raise AuthorityUnavailable("absolute installed package root required")
        result = verify_installed_backend_runtime_v1(root, trusted_manifest_sha256)
        if not result.verified:
            raise AuthorityUnavailable("administrator-pinned backend package is unverified: " + result.reason)
        if (type(authority_uid) is not int or authority_uid < 0
                or not peer_scopes or not profile_peers):
            raise AuthorityUnavailable("explicit installed service and peer identities required")
        scopes = dict(peer_scopes)
        profiles = dict(profile_peers)
        for certificate, scope in scopes.items():
            if (type(certificate) is not str or len(certificate) != 64
                    or any(c not in "0123456789abcdef" for c in certificate)
                    or type(scope) is not InstalledPeerScopeV1):
                raise AuthorityUnavailable("installed peer scope is invalid")
        for profile, certificate in profiles.items():
            identifier(profile, "profile_id")
            if certificate not in scopes:
                raise AuthorityUnavailable("profile has no installed certificate scope")
        self._scopes, self._profiles = scopes, profiles
        self._package_root, self._manifest_pin = root.resolve(strict=True), trusted_manifest_sha256
        self._authority_uid, self._issuer = authority_uid, object()

    def _local_identity(self):
        if os.name == "nt":
            return _effective_windows_administrator()
        return os.name == "posix" and os.geteuid() in {0, self._authority_uid}

    def local_administrator_credential(self, action, namespace):
        identifier(namespace, "namespace")
        if (action not in _LOCAL or namespace not in {s.namespace for s in self._scopes.values()}
                or not self._local_identity()):
            raise AuthorityUnavailable("installed local service credential unavailable")
        return _LocalAdministratorCredential(action, namespace, self._issuer)

    def core_authorizer(self, credential, action, namespace, holder):
        if type(credential) is _LocalAdministratorCredential:
            permitted = (credential.action == action
                or credential.action == "c04_execute" and action in {"execution", "current"}
                or credential.action == "c09_maintenance" and action in _C09)
            return (credential._issuer is self._issuer and credential.namespace == namespace
                    and permitted and self._local_identity())
        if type(credential) is not MtlsPeerCredential or action not in _PEER:
            return False
        scope = self._scopes.get(credential.certificate_sha256)
        return (scope is not None and scope.namespace == namespace
                and (holder is None or scope.holder == holder))

    def administrator_authorizer(self, credential, action, namespace, holder):
        if action == "pair" and namespace == "authority:enrollment":
            return (type(credential) is MtlsPeerCredential
                    and self._profiles.get(holder) == credential.certificate_sha256)
        return self.core_authorizer(credential, action, namespace, holder)

    def publisher_manifest_verifier(self, profile_id, plugin_name, host_api_version, manifest_sha256):
        if (profile_id not in self._profiles or plugin_name != "astrbot_plugin_sylanne"
                or host_api_version != "4.28.1" or manifest_sha256 != self._manifest_pin):
            return False
        manifest = self._package_root / "release-manifest.json"
        return (manifest.is_file() and not manifest.is_symlink()
                and hashlib.sha256(manifest.read_bytes()).hexdigest() == self._manifest_pin)
