"""Signed Owner identity bound to one Dashboard user and installed Authority.

This layer authenticates identity only. D12 graph authority and installation
management grants are checked independently by their respective services.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
from threading import RLock

from ..authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
)
from ..runtime_contracts import namespace_ref
from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class InstallationOwnerIdentityV1:
    username: str
    request: OwnerSessionLoginRequestV1
    session_id: str


class InstallationOwnerSessionsV1:
    def __init__(self, *, authority, namespace, authority_id, installation_id, origin):
        if (type(namespace) is not NamespaceId
                or not all(type(x) is str and x for x in (authority_id, installation_id, origin))
                or not origin.startswith(("http://", "https://"))
                or not all(callable(getattr(authority, name, None)) for name in (
                    "begin_owner_session", "accept_owner_session", "describe_owner_session",
                    "logout_owner_session"))):
            raise TypeError("installed Owner identity authority is required")
        self._authority = authority
        self._namespace, self._authority_namespace = namespace, namespace_ref(namespace)
        self._authority_id, self._installation_id, self._origin = authority_id, installation_id, origin
        self._secret = secrets.token_bytes(32)
        self._lock = RLock()
        self._bindings = {}
        self._pending = {}
        self._revoked = set()
        self._closed = False

    @property
    def origin(self):
        return self._origin

    @property
    def namespace(self):
        return self._namespace

    def _key(self, token):
        if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            raise ValueError("Owner token is invalid")
        return hmac.new(self._secret, token.encode(), hashlib.sha256).digest()

    def _request_matches(self, request):
        return (type(request) is OwnerSessionLoginRequestV1
                and request.authority_id == self._authority_id
                and request.authority_namespace == self._authority_namespace
                and request.installation_id == self._installation_id
                and request.dashboard_origin == self._origin
                and request.audience == "owner")

    async def begin_signed_login(self, *, request, login_request):
        if (self._closed or type(request.username) is not str or not request.username
                or request.headers.get("origin") != self._origin
                or not self._request_matches(login_request)):
            raise ValueError("authenticated installed Owner request is required")
        challenge = await asyncio.to_thread(self._authority.begin_owner_session,
            namespace=self._namespace, authority_namespace=self._authority_namespace, request=login_request)
        if type(challenge) is not OwnerSessionLoginChallengeV1 or challenge.request != login_request:
            raise RuntimeError("Authority challenge identity differs")
        with self._lock:
            if self._closed:
                raise RuntimeError("Owner identity service is closed")
            if len(self._pending) >= 128:
                self._pending.pop(next(iter(self._pending)))
            self._pending[challenge.nonce] = (request.username, challenge)
        return challenge

    async def complete_signed_login(self, *, request, challenge, signature):
        if (self._closed or type(request.username) is not str or not request.username
                or request.headers.get("origin") != self._origin
                or type(challenge) is not OwnerSessionLoginChallengeV1
                or not self._request_matches(challenge.request) or type(signature) is not bytes):
            raise ValueError("authenticated signed Owner request is required")
        with self._lock:
            pending = self._pending.pop(challenge.nonce, None)
            if pending != (request.username, challenge):
                raise ValueError("challenge belongs to another Dashboard user or was consumed")
        token = await asyncio.to_thread(self._authority.accept_owner_session,
            namespace=self._namespace, authority_namespace=self._authority_namespace,
            challenge=challenge, signature=signature)
        try:
            described = await asyncio.to_thread(self._authority.describe_owner_session,
                namespace=self._namespace, authority_namespace=self._authority_namespace, token=token)
            if described != challenge.request or not self._request_matches(described):
                raise RuntimeError("accepted Owner identity differs")
            key = self._key(token)
            with self._lock:
                if self._closed or key in self._revoked or key in self._bindings:
                    raise RuntimeError("Owner identity was closed, revoked or already bound")
                self._bindings[key] = InstallationOwnerIdentityV1(
                    request.username, described, "owner:" + key.hex())
        except Exception:
            try:
                await asyncio.to_thread(self._authority.logout_owner_session,
                    namespace=self._namespace, authority_namespace=self._authority_namespace,
                    request=challenge.request, token=token)
            except Exception:
                pass
            raise
        return token

    async def resolve_current_identity(self, *, username, owner_session_token):
        try:
            key = self._key(owner_session_token)
        except ValueError:
            return None
        with self._lock:
            binding = self._bindings.get(key)
            if self._closed or binding is None or binding.username != username:
                return None
        try:
            described = await asyncio.to_thread(self._authority.describe_owner_session,
                namespace=self._namespace, authority_namespace=self._authority_namespace,
                token=owner_session_token)
        except (RuntimeError, ValueError, TypeError, PermissionError):
            return None
        if described != binding.request or not self._request_matches(described):
            return None
        with self._lock:
            if self._closed or self._bindings.get(key) != binding or key in self._revoked:
                return None
        return binding

    async def revoke_bound_session(self, *, username, owner_session_token):
        try:
            key = self._key(owner_session_token)
        except ValueError:
            return False
        with self._lock:
            binding = self._bindings.get(key)
            if binding is None or binding.username != username:
                return False
            self._bindings.pop(key)
            self._revoked.add(key)
            self._pending = {nonce: value for nonce, value in self._pending.items() if value[0] != username}
        await asyncio.to_thread(self._authority.logout_owner_session,
            namespace=self._namespace, authority_namespace=self._authority_namespace,
            request=binding.request, token=owner_session_token)
        return True

    def close(self):
        with self._lock:
            self._closed = True
            self._bindings.clear()
            self._pending.clear()
            self._revoked.clear()
