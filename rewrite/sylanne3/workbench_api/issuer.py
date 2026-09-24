"""Graph-backed, fail-closed read issuer for the D12 workbench.

The HTTP layer authenticates a browser session; this adapter converts that
session into an authority-issued coordinator lease.  It deliberately owns no
graph state and does not manufacture operation receipts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_types import GraphPage
from ..graph_coordinator import RoleInitializationReceiptV1, SceneBindingReceiptV1
from ..domains.d01 import ActiveRoleQualification
from ..domains.d03.context import RoleBindingResolution
from ..runtime_contracts import AuthorityContext
from .domain_registry import PROJECTION_CONTEXT_V1
from .onboarding import OnboardingPolicyResolver, TrustedBindScene, TrustedCreateCharacter
from .d01_onboarding import VerifiedCreationResources
from .service import AuthenticatedSession, request_digest


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
                 view_registry: DomainViewRegistry,
                 onboarding: OnboardingPolicyResolver | None = None) -> None:
        if not callable(getattr(coordinator, "query", None)):
            raise TypeError("coordinator must expose query")
        if not callable(getattr(grants, "resolve", None)):
            raise TypeError("grants must expose resolve")
        if not callable(getattr(view_registry, "view_types", None)):
            raise TypeError("view_registry must expose view_types")
        self._coordinator = coordinator
        self._grants = grants
        self._view_registry = view_registry
        self._onboarding = onboarding

    def read_projection(self, *, session: AuthenticatedSession, scope: str, view_type: str,
                        purpose: str, audience: str) -> Mapping[str, Any]:
        if not session.allows(scope, "workbench.read", purpose, audience):
            return _unavailable("authority_unavailable")
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
            context_version = self._context_version(grant, view_type)
        except (TypeError, ValueError, LookupError):
            return _unavailable("field_projection_unavailable")
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
            if context_version == PROJECTION_CONTEXT_V1:
                projected = projector(grant.authority, view_type, atoms,
                                      audience=audience, purpose=purpose)
            else:
                projected = projector(grant.authority, view_type, atoms)
        except Exception:
            return _unavailable("field_projection_unavailable")
        if not isinstance(projected, Mapping):
            return _unavailable("invalid_field_projection")
        projection = {
            "view_type": view_type,
            "namespace": {"bot": epoch.bot, "persona": epoch.persona},
            "data": dict(projected),
            "access_generation": grant.authority.activation_generation,
        }
        if context_version is None:
            projection["snapshot_epoch"] = epoch.revision
            projection["coverage"] = {"requested_types": types, "returned_atoms": len(atoms),
                                      "truncated": page.next_after is not None}
            projection["next_cursor"] = (page.next_after.token
                                         if page.next_after is not None else None)
        return {"status": "ready", "projection": projection}

    def open_workspace(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                       audience: str) -> Mapping[str, Any]:
        if not session.allows(scope, "workbench.read", purpose, audience):
            return _unavailable("authority_unavailable")
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
                context_version = self._context_version(grant, name)
            except (TypeError, ValueError, LookupError):
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
            entry = {"view_type": name, "status": "available"}
            if context_version is None:
                entry["snapshot_epoch"] = epoch.revision
                entry["cursor"] = page.next_after.token if page.next_after else None
            entries.append(entry)
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
        if action == "create_character":
            return self._create_character(session=session, scope=scope, purpose=purpose,
                                          audience=audience, operation_id=operation_id,
                                          input_data=input_data)
        if action == "bind_scene":
            return self._bind_scene(session=session, scope=scope, purpose=purpose,
                                    audience=audience, operation_id=operation_id,
                                    input_data=input_data)
        return _unavailable("action_issuer_unavailable")

    def _bind_scene(self, *, session: AuthenticatedSession, scope: str,
                    purpose: str, audience: str, operation_id: str,
                    input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        from ..host.current_scene import CurrentHostScene

        if not session.allows(scope, "workbench.bind_scene", purpose, audience):
            return _unavailable("authority_unavailable")
        if (type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1):
            return _unavailable("signed_owner_session_unavailable")
        resolver = self._onboarding
        commit = getattr(self._coordinator, "commit_scene_binding_v2", None)
        if resolver is None or not callable(commit):
            return _unavailable("scene_binding_unavailable")
        digest = "sha256:" + request_digest({
            "action": "bind_scene", "scope": scope, "purpose": purpose,
            "audience": audience, "operation_id": operation_id, "input": input_data,
        })
        selected_scene = input_data.get("scene_ref")
        selected_visibility = input_data.get("visibility")
        if (type(selected_scene) is not str or type(selected_visibility) is not str
                or input_data.get("acknowledgement") is not True):
            return _unavailable("scene_binding_policy_unavailable")
        replay = getattr(resolver, "replay_committed_bind_scene", None)
        result = (replay(
            coordinator=self._coordinator, session=session, scope=scope,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=digest,
        ) if callable(replay) else None)
        resolved = None
        if result is None:
            resolved = resolver.resolve_bind_scene(
                coordinator=self._coordinator, session=session, scope=scope,
                purpose=purpose, audience=audience, operation_id=operation_id,
                request_digest=digest, input_data=input_data,
            )
            if (not isinstance(resolved, TrustedBindScene)
                    or resolved.actor_id != session.actor_id
                    or resolved.session_id != session.session_id
                    or resolved.scope != scope or resolved.operation_id != operation_id
                    or resolved.request_digest != digest
                    or type(resolved.scene) is not CurrentHostScene
                    or not isinstance(resolved.active_role, ActiveRoleQualification)
                    or not isinstance(resolved.prior, RoleBindingResolution)
                    or resolved.scene.namespace != resolved.active_role.namespace
                    or resolved.scene.scene_ref != selected_scene
                    or resolved.scene.visibility != selected_visibility
                    or resolved.prior.status != "no_applicable_binding"
                    or resolved.prior.request is None
                    or resolved.prior.request.scene_ref != selected_scene):
                return _unavailable("scene_binding_policy_unavailable")
            result = commit(namespace=resolved.active_role.namespace,
                            operation_id=operation_id, scene=resolved.scene,
                            prior=resolved.prior, principal=resolved.principal,
                            actor_id=resolved.actor_id, request_digest=digest,
                            owner_session_token=session.owner_session_token,
                            owner_session_request=session.owner_session_request)
        if (not isinstance(result, SceneBindingReceiptV1)
                or scope != f"{result.namespace.bot_id}/{result.namespace.persona_id}"
                or result.operation_id != operation_id
                or result.request_digest != digest
                or result.scene_ref != selected_scene
                or not result.binding_id or not result.role_head_id
                or not result.owner_authorization_head.startswith("sha256:")
                or (resolved is not None and (
                    result.namespace != resolved.active_role.namespace
                    or result.role_head_id != resolved.active_role.head_id
                    or result.owner_authorization_head != resolved.authorization_head))):
            return _unavailable("scene_binding_receipt_invalid")
        return {"status": "ready", "receipt": {
            "operation_id": operation_id, "phase": "scene_bound",
            "scene_ref": result.scene_ref, "binding_id": result.binding_id,
            "binding_revision": 1,
            "role_head_id": result.role_head_id,
            "graph_revision": result.graph_revision,
        }}

    def _create_character(self, *, session: AuthenticatedSession, scope: str,
                          purpose: str, audience: str, operation_id: str,
                          input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        if not session.allows(scope, "workbench.create", purpose, audience):
            return _unavailable("authority_unavailable")
        if (type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1):
            return _unavailable("signed_owner_session_unavailable")
        resolver = self._onboarding
        commit = getattr(self._coordinator, "commit_role_initialization_v2", None)
        if resolver is None or not callable(commit):
            return _unavailable("role_initialization_unavailable")
        digest = "sha256:" + request_digest({
            "action": "create_character", "scope": scope, "purpose": purpose,
            "audience": audience, "operation_id": operation_id, "input": input_data,
        })
        replay = getattr(resolver, "replay_committed_create_character", None)
        result = (replay(
            coordinator=self._coordinator, session=session, scope=scope,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=digest,
        ) if callable(replay) else None)
        if result is None:
            resolved = resolver.resolve_create_character(
                session=session, scope=scope, purpose=purpose, audience=audience,
                operation_id=operation_id, request_digest=digest, input_data=input_data,
            )
            if resolved is None:
                reject = getattr(resolver, "reject_unresolvable_create_character", None)
                if callable(reject) and reject(
                        coordinator=self._coordinator, session=session, scope=scope,
                        purpose=purpose, audience=audience, operation_id=operation_id,
                        request_digest=digest):
                    return _unavailable("role_initialization_terminal_rejected_no_commit")
            if (not isinstance(resolved, TrustedCreateCharacter)
                    or resolved.actor_id != session.actor_id
                    or resolved.session_id != session.session_id
                    or resolved.scope != scope or resolved.operation_id != operation_id
                    or resolved.request_digest != digest
                    or type(resolved.resources) is not VerifiedCreationResources):
                return _unavailable("role_initialization_policy_unavailable")
            result = commit(namespace=resolved.plan.namespace, operation_id=operation_id,
                            request_digest=digest, plan=resolved.plan,
                            principal=resolved.principal, resources=resolved.resources,
                            actor_id=resolved.actor_id,
                            owner_session_token=session.owner_session_token,
                            owner_session_request=session.owner_session_request)
            expected_namespace = resolved.plan.namespace
            expected_plan_id = resolved.plan.plan_id
            expected_head_id = resolved.plan.head_id
        else:
            if not isinstance(result, RoleInitializationReceiptV1):
                return _unavailable("role_initialization_receipt_invalid")
            expected_namespace = result.namespace
            expected_plan_id = result.plan_id
            expected_head_id = result.head_id
        if (not isinstance(result, RoleInitializationReceiptV1)
                or result.namespace != expected_namespace
                or result.operation_id != operation_id or result.request_digest != digest
                or result.plan_id != expected_plan_id
                or result.head_id != expected_head_id
                or scope != f"{result.namespace.bot_id}/{result.namespace.persona_id}"
                or result.owner_grant_revision < 1):
            return _unavailable("role_initialization_receipt_invalid")
        return {"status": "ready", "receipt": {
            "operation_id": operation_id, "phase": "role_initialized",
            "role_ref": f"persona:{result.namespace.persona_id}",
            "plan_id": result.plan_id, "head_id": result.head_id,
            "owner_grant_id": result.owner_grant_id,
            "owner_grant_revision": result.owner_grant_revision,
            "graph_revision": result.graph_revision,
        }}

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

    def _context_version(self, grant: CoordinatorGrant, view_type: str) -> str | None:
        resolver = getattr(self._view_registry, "projection_context_version", None)
        if resolver is None:
            return None
        if not callable(resolver):
            raise TypeError("invalid projection context resolver")
        version = resolver(grant.authority, view_type)
        if version not in (None, PROJECTION_CONTEXT_V1):
            raise ValueError("unsupported projection context version")
        return version

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
