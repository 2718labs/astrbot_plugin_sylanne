"""Graph-backed, fail-closed read issuer for the D12 workbench.

The HTTP layer authenticates a browser session; this adapter converts that
session into an authority-issued coordinator lease.  It deliberately owns no
graph state and does not manufacture operation receipts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from ..graph_types import GraphPage
from ..runtime_contracts import AuthorityContext
from .service import AuthenticatedSession


@dataclass(frozen=True)
class CoordinatorGrant:
    """A server-issued, already scoped coordinator authority and lease."""

    scope: str
    authority: AuthorityContext
    lease: object

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not self.scope:
            raise ValueError("grant scope is required")


class GrantResolver(Protocol):
    """Resolve the authenticated session on the server, never from JSON."""

    def resolve(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                audience: str) -> CoordinatorGrant | None: ...


class DomainViewRegistry(Protocol):
    """Current authoritative registry of public D12 view projections."""

    def view_types(self, authority: AuthorityContext) -> Mapping[str, tuple[str, ...]]: ...

    def view_owner_kind(self, authority: AuthorityContext, view_type: str) -> str | None: ...

    def project_workbench(self, authority: AuthorityContext, view_type: str,
                          atoms: tuple[Mapping[str, Any], ...]) -> Mapping[str, Any]: ...


class GraphWorkbenchIssuer:
    """Thin D12 issuer over ``GraphCoordinator.query``.

    It supports only C01 and C04.  The remaining D12 commands require their
    respective domain issuers and deliberately return ``unavailable`` here.
    """

    def __init__(self, coordinator: object, grants: GrantResolver,
                 view_registry: DomainViewRegistry) -> None:
        if not callable(getattr(coordinator, "query", None)):
            raise TypeError("coordinator must expose query")
        if not callable(getattr(grants, "resolve", None)):
            raise TypeError("grants must expose resolve")
        if not callable(getattr(view_registry, "view_types", None)):
            raise TypeError("view_registry must expose view_types")
        self._coordinator = coordinator
        self._grants = grants
        self._view_registry = view_registry

    def read_projection(self, *, session: AuthenticatedSession, scope: str, view_type: str,
                        purpose: str, audience: str) -> Mapping[str, Any]:
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None:
            return _unavailable("authority_unavailable")
        views = self._views(grant)
        if views is None:
            return _unavailable("domain_registry_unavailable")
        types = views.get(view_type)
        if types is None:
            return _unavailable("view_unsupported")
        owner_kind = self._owner_kind(grant, view_type)
        if owner_kind is None:
            return _unavailable("view_unsupported")
        try:
            page = self._coordinator.query(grant.authority, grant.lease,
                                           type_names=types, owner_kind=owner_kind, limit=100)
        except PermissionError:
            raise
        except Exception:
            return _unavailable("graph_query_unavailable")
        if not isinstance(page, GraphPage):
            return _unavailable("invalid_graph_snapshot")
        snapshot = page.snapshot
        epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
        if epoch is None:
            return _unavailable("incomplete_graph_snapshot")
        if ((epoch.bot, epoch.persona) != grant.authority.namespace.as_tuple
                or any(atom.key.owner.kind != owner_kind
                       or (atom.key.owner.bot, atom.key.owner.persona)
                       != grant.authority.namespace.as_tuple
                       or atom.key.type_name not in types for atom in snapshot.atoms)):
            return _unavailable("invalid_graph_snapshot")
        atoms = tuple({
            "type": atom.key.type_name,
            "name": atom.key.name,
            "revision": atom.revision,
            "value": atom.value,
        } for atom in snapshot.atoms)
        projector = getattr(self._view_registry, "project_workbench", None)
        if not callable(projector):
            return _unavailable("field_projection_unavailable")
        try:
            projected = projector(grant.authority, view_type, atoms)
        except Exception:
            return _unavailable("field_projection_unavailable")
        if not isinstance(projected, Mapping):
            return _unavailable("invalid_field_projection")
        return {
            "status": "ready",
            "projection": {
                "view_type": view_type,
                "namespace": {"bot": epoch.bot, "persona": epoch.persona},
                "snapshot_epoch": epoch.revision,
                "coverage": {"requested_types": types, "returned_atoms": len(atoms),
                             "truncated": page.next_after is not None},
                "data": dict(projected),
                "next_cursor": page.next_after.token if page.next_after is not None else None,
                "access_generation": grant.authority.activation_generation,
            },
        }

    def open_workspace(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                       audience: str) -> Mapping[str, Any]:
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None:
            return _unavailable("authority_unavailable")
        views = self._views(grant)
        if views is None:
            return _unavailable("domain_registry_unavailable")
        entries = []
        for name, types in sorted(views.items()):
            owner_kind = self._owner_kind(grant, name)
            if owner_kind is None:
                entries.append({"view_type": name, "status": "unavailable"})
                continue
            try:
                page = self._coordinator.query(grant.authority, grant.lease, type_names=types,
                                               owner_kind=owner_kind, limit=1)
            except PermissionError:
                raise
            except Exception:
                entries.append({"view_type": name, "status": "unavailable"})
                continue
            if (not isinstance(page, GraphPage) or len(page.snapshot.epochs) != 1
                    or page.snapshot.epochs[0].bot != grant.authority.namespace.bot_id
                    or page.snapshot.epochs[0].persona != grant.authority.namespace.persona_id
                    or any(atom.key.owner.kind != owner_kind
                           or atom.key.type_name not in types
                           or (atom.key.owner.bot, atom.key.owner.persona)
                           != grant.authority.namespace.as_tuple for atom in page.snapshot.atoms)):
                entries.append({"view_type": name, "status": "unavailable"})
                continue
            epoch = page.snapshot.epochs[0]
            entries.append({"view_type": name, "status": "available",
                            "snapshot_epoch": epoch.revision,
                            "cursor": page.next_after.token if page.next_after else None})
        return {"status": "ready", "projection": {
            "namespace": {"bot": grant.authority.namespace.bot_id,
                          "persona": grant.authority.namespace.persona_id},
            "access_generation": grant.authority.activation_generation,
            "views": tuple(entries),
            "unavailable_domains": self._unavailable_domains(grant),
        }}

    def execute(self, *, session: AuthenticatedSession, action: str, scope: str,
                purpose: str, audience: str, operation_id: str,
                input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        return _unavailable("action_issuer_unavailable")

    def _views(self, grant: CoordinatorGrant) -> Mapping[str, tuple[str, ...]] | None:
        try:
            views = self._view_registry.view_types(grant.authority)
        except Exception:
            return None
        if not isinstance(views, Mapping):
            return None
        checked: dict[str, tuple[str, ...]] = {}
        for name, types in views.items():
            if (not isinstance(name, str) or not name or not isinstance(types, tuple)
                    or not types or not all(isinstance(item, str) and item for item in types)):
                return None
            checked[name] = types
        return checked

    def _owner_kind(self, grant: CoordinatorGrant, view_type: str) -> str | None:
        resolver = getattr(self._view_registry, "view_owner_kind", None)
        if not callable(resolver):
            return None
        try:
            owner_kind = resolver(grant.authority, view_type)
        except Exception:
            return None
        if not isinstance(owner_kind, str) or owner_kind not in grant.authority.owner_scope:
            return None
        return owner_kind

    def _unavailable_domains(self, grant: CoordinatorGrant) -> tuple[Mapping[str, str], ...]:
        catalogue = getattr(self._view_registry, "catalogue", None)
        if not callable(catalogue):
            return ()
        try:
            unavailable = catalogue(grant.authority).unavailable_domains
        except Exception:
            return ()
        if not isinstance(unavailable, Mapping):
            return ()
        return tuple({"domain": domain, "reason": reason}
                     for domain, reason in sorted(unavailable.items())
                     if isinstance(domain, str) and isinstance(reason, str))

    def _resolve(self, session: AuthenticatedSession, scope: str, purpose: str,
                 audience: str) -> CoordinatorGrant | None:
        grant = self._grants.resolve(session=session, scope=scope, purpose=purpose,
                                     audience=audience)
        if not isinstance(grant, CoordinatorGrant):
            return None
        # The resolved authority is authoritative; reject a resolver that tried
        # to bind this browser scope to a different session/purpose/audience.
        if (grant.scope != scope or grant.authority.actor != session.actor_id
                or grant.authority.purpose != purpose
                or audience not in grant.authority.audience):
            return None
        return grant


def _unavailable(code: str) -> Mapping[str, Any]:
    return {"status": "unavailable", "problem": {"code": code, "retryable": True}}


__all__ = ("CoordinatorGrant", "GrantResolver", "DomainViewRegistry", "GraphWorkbenchIssuer")
