"""Graph-backed, fail-closed read issuer for the D12 workbench.

The HTTP layer authenticates a browser session; this adapter converts that
session into an authority-issued coordinator lease.  It deliberately owns no
graph state and does not manufacture operation receipts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Mapping, Protocol

from ..runtime.lifecycle_operations_v1 import D12PrerequisiteUnavailable, D12OperationPending
from ..runtime.local_module_admission_v1 import LocalModuleAdmissionDeniedV1
from ..contracts import StaleRead
from ..authority_service.v2_contract import (
    DeletionMutationReceiptV1, FencePermitV2, deletion_scope_digest,
)
from ..authority_service.current_accepted_erasure_read import CurrentAcceptedErasureV1
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_types import AtomKey, GraphPage, NamespaceEpoch
from ..graph_coordinator import (
    RoleInitializationReceiptV1, SceneBindingReceiptV1,
    SourceAccessRevocationReceiptV1,
    WorkbenchProjectionSnapshotV1,
)
from ..domains.d01 import ActiveRoleQualification
from ..domains.d03.context import RoleBindingResolution
from ..domains.d12.scheme_command import (
    D12CreatorDraftReadPort, D12SchemeAdoptionReceiptV1,
    D12SchemeCommandIssuer, D12SchemeHold, D12IsolatedPreviewV1,
)
from ..domains.d12.d09_preview import D12D09PreviewReportV1
from ..runtime.d12_scheme_behavior_preview_v1 import D12BehaviorExperimentReportV1
from ..runtime.scheme_original_store_v1 import CompilationOriginalV1, PreviewOriginalV1
from ..runtime_contracts import AuthorityContext, canonical_digest
from ..domains.d12.scoped_erasure import D12ScopedErasureRequestV2
from ..domains.d12.backend_operation_contracts_v1 import D12BackendOperationOriginalV1
from .domain_registry import PROJECTION_CONTEXT_V1, PROJECTION_CONTEXT_V2
from .onboarding import OnboardingPolicyResolver, TrustedBindScene, TrustedCreateCharacter
from .d01_onboarding import VerifiedCreationResources
from .service import AuthenticatedSession, request_digest as digest_payload
from .support_export import write_view_status_export_v1
from .source_correction import SourceCorrectionCommitReceiptV1, SourceCorrectionRequestV1

_BACKEND_ROUTES = {
    "prepare_transfer": ("prepare_current_transfer_v1", "transfer_plan", "workbench.transfer"),
    "execute_transfer": ("execute_current_transfer_v1", "transfer_execution", "workbench.transfer"),
    "configure_or_control": ("commit_current_control_v1", "control", "workbench.control"),
    "install_or_upgrade": ("install_or_upgrade_v1", "maintenance", "workbench.maintain"),
    "run_experiment": ("run_current_experiment_v1", "experiment", "workbench.experiment"),
    "diagnose_and_export_support": ("export_current_support_v1", "support_export", "workbench.diagnose"),
}


@dataclass(frozen=True)
class CoordinatorGrant:
    """A server-issued, already scoped coordinator authority and lease."""

    scope: str
    authority: AuthorityContext
    lease: object
    capabilities: frozenset[str] = frozenset()
    owner_grant_ref: str | None = None
    owner_grant_revision: int | None = None
    owner_grant_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not self.scope:
            raise ValueError("grant scope is required")
        if (type(self.capabilities) is not frozenset
                or any(type(item) is not str or not item
                       for item in self.capabilities)):
            raise ValueError("grant capabilities must be a typed set")


class GrantResolver(Protocol):
    """Resolve the authenticated session on the server, never from JSON."""

    def resolve(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                audience: str) -> CoordinatorGrant | None: ...


class D04RootResourceResolver(Protocol):
    """Resolve formal installed root bytes and a dedicated signed D11 lease."""

    def resolve_current_d04_root_resources(
        self, *, namespace: object, session: AuthenticatedSession,
    ) -> tuple[object, str] | None: ...


class DomainViewRegistry(Protocol):
    """Current authoritative registry of public D12 view projections."""

    def view_types(self, authority: AuthorityContext) -> Mapping[str, tuple[str, ...]]: ...

    def view_owner_kind(self, authority: AuthorityContext, view_type: str) -> str | None: ...

    def project_workbench(self, authority: AuthorityContext, view_type: str,
                          atoms: tuple[Mapping[str, Any], ...]) -> Mapping[str, Any]: ...


class GraphWorkbenchIssuer:
    """Thin D12 issuer over ``GraphCoordinator.query``.

    It supports C01/C04 reads and dedicated Owner-gated creation, scene and
    source-correction ports. Other commands require their domain issuers.
    """

    def __init__(self, coordinator: object, grants: GrantResolver,
                 view_registry: DomainViewRegistry,
                 onboarding: OnboardingPolicyResolver | None = None,
                 correction_installation_policy: object | None = None,
                 correction_admin_policy: object | None = None,
                 scheme_port: D12CreatorDraftReadPort | None = None,
                 d04_root_resource_resolver: D04RootResourceResolver | None = None,
                 support_export_root: Path | None = None,
                 erasure_prepare: object | None = None,
                 erasure_accepted_read: object | None = None,
                 backend_operation_port: object | None = None,
                 maintenance_port: object | None = None,
                 package_maintenance_port: object | None = None) -> None:
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
        self._correction_installation_policy = correction_installation_policy
        self._correction_admin_policy = correction_admin_policy
        self._scheme_commands = (D12SchemeCommandIssuer(scheme_port)
                                 if scheme_port is not None else None)
        self._scheme_port = scheme_port
        self._d04_root_resource_resolver = d04_root_resource_resolver
        self._support_export_root = support_export_root
        self._erasure_prepare = erasure_prepare if callable(erasure_prepare) else None
        self._erasure_accepted_read = (erasure_accepted_read
                                       if callable(erasure_accepted_read) else None)
        self._backend_operation_port = backend_operation_port or coordinator
        self._maintenance_port = maintenance_port
        from ..host.d12_package_workbench_port_v2 import InstalledD12PackageWorkbenchPortV2
        if package_maintenance_port is not None and type(package_maintenance_port) is not InstalledD12PackageWorkbenchPortV2:
            raise TypeError("actual paired package maintenance port required")
        self._package_maintenance_port = package_maintenance_port

    def read_owner_artifact_project_context_options(self, *, session: AuthenticatedSession,
            scope: str, purpose: str, audience: str) -> Mapping[str, Any]:
        if (not session.allows(scope, "workbench.read", purpose, audience)
                or not session.allows(scope, "workbench.create", purpose, audience)):
            return _unavailable("authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience, domains=("d03", "d08", "d10", "d11", "d12"))
        if grant is None or "workbench.create" not in grant.capabilities:
            return _unavailable("authority_unavailable")
        try:
            projection = self._coordinator.read_current_owner_artifact_project_context_choices_v1(
                grant.authority, grant.lease)
        except StaleRead:
            return {"status": "stale", "problem": {"code": "project_context_basis_changed", "retryable": True}}
        except PermissionError:
            raise
        except (ValueError, RuntimeError, LookupError):
            return _unavailable("project_context_unavailable")
        if (type(projection) is not dict
                or projection.get("schema") != "d03.owner-artifact-project-context-options.v1"
                or projection.get("namespace") != asdict(grant.authority.namespace)):
            return _unavailable("project_context_unavailable")
        return {"status": "ready", "projection": projection}

    def read_owner_material_source_status_v1(self, *, session, scope, purpose, audience, input_data):
        if (audience!='owner' or purpose!='workbench_view'
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token or not session.allows(scope,'workbench.read',purpose,audience)):
            return _unavailable('owner_material_read_authority_unavailable')
        grant=self._resolve(session,scope,purpose,audience,domains=('d06','d11'))
        if grant is None or 'workbench.read' not in grant.capabilities:
            return _unavailable('owner_material_read_authority_unavailable')
        return {'status':'ready','projection':self._coordinator.read_owner_material_source_status_v1(
            grant.authority,grant.lease,**input_data)}

    def read_owner_source_note_task_v1(self, *, session, scope, purpose, audience, input_data, options):
        if (audience != 'owner' or purpose != 'workbench_view'
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token or not session.allows(scope,'workbench.read',purpose,audience)):
            return _unavailable('owner_source_note_task_read_authority_unavailable')
        grant=self._resolve(session,scope,purpose,audience,
            domains=('d02','d03','d06','d08','d10','d11') if options else ('d08','d11'))
        if grant is None or 'workbench.read' not in grant.capabilities:
            return _unavailable('owner_source_note_task_read_authority_unavailable')
        if options:
            projection=self._coordinator.read_owner_source_note_task_options_v1(grant.authority,grant.lease,**input_data)
        else:
            projection=self._coordinator.read_owner_source_note_task_status_v1(grant.authority,grant.lease,**input_data)
        return {'status':'ready','projection':projection}

    def read_owner_project_artifact_v1(self, *, session, scope, purpose, audience, input_data, options=False):
        if (audience != "owner" or purpose != "workbench_view"
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token
                or not session.allows(scope, "workbench.read", purpose, audience)):
            return _unavailable("artifact_read_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience, domains=("d08", "d10", "d11", "d12"))
        if grant is None or "workbench.read" not in grant.capabilities:
            return _unavailable("artifact_read_authority_unavailable")
        try:
            if options:
                projection = self._coordinator.read_owner_project_artifact_options_v1(
                    grant.authority, grant.lease, project_ref=input_data['project_ref'])
            else:
                from ..runtime.d12_owner_artifact_read_v1 import OwnerArtifactReadRequestV1
                port = self._coordinator._GraphCoordinator__content_fence_v2
                request = OwnerArtifactReadRequestV1(namespace=grant.authority.namespace,
                    installation_id=port.installation_grant.installation_id, **input_data)
                projection = self._coordinator.read_owner_project_artifact_v1(grant.authority, grant.lease, request=request)
        except StaleRead:
            return {"status": "stale", "problem": {"code": "artifact_version_changed", "retryable": False}}
        except PermissionError:
            raise
        except (ValueError, RuntimeError, LookupError):
            return _unavailable("artifact_current_read_unavailable")
        return {"status": "ready", "projection": projection}

    def read_project_control_context_v1(self, *, session, scope, purpose, audience, project_ref):
        return self._read_project_control_context_v1(version=1, session=session,
            scope=scope, purpose=purpose, audience=audience, project_ref=project_ref)

    def read_project_control_context_v2(self, *, session, scope, purpose, audience, project_ref):
        return self._read_project_control_context_v1(version=2, session=session,
            scope=scope, purpose=purpose, audience=audience, project_ref=project_ref)

    def _read_project_control_context_v1(self, *, session, scope, purpose, audience, project_ref, version):
        if (audience != "owner" or purpose != "workbench_user_action"
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token
                or not session.allows(scope, "workbench.read", purpose, audience)
                or not session.allows(scope, "workbench.control", purpose, audience)):
            return _unavailable("project_control_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience, domains=("d08", "d10", "d11", "d12"))
        if grant is None or "workbench.control" not in grant.capabilities:
            return _unavailable("project_control_authority_unavailable")
        try:
            reader = (self._coordinator.read_project_control_context_v1 if version == 1
                else self._coordinator.read_project_control_context_v2)
            projection = reader(grant.authority, grant.lease, project_ref=project_ref)
        except StaleRead:
            return {"status": "stale", "problem": {"code": "project_control_basis_changed", "retryable": True}}
        except PermissionError:
            raise
        except (ValueError, RuntimeError, LookupError):
            return _unavailable("project_control_context_unavailable")
        return {"status": "ready", "projection": projection}

    def execute_project_control_v1(self, *, session, action, scope, purpose, audience, operation_id, input_data):
        from ..runtime.d08_project_control_v1 import PauseProjectRequestV1, ResumeProjectRequestV1
        if (audience != "owner" or purpose != "workbench_user_action"
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token
                or not session.allows(scope, "workbench.control", purpose, audience)):
            return _unavailable("project_control_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience, domains=("d08", "d10", "d11", "d12"))
        if grant is None or "workbench.control" not in grant.capabilities:
            return _unavailable("project_control_authority_unavailable")
        request_type = PauseProjectRequestV1 if action == "pause_project_v1" else ResumeProjectRequestV1
        request = request_type(**input_data)
        try:
            commit = self._coordinator.pause_project_v1 if action == "pause_project_v1" else self._coordinator.resume_project_v1
            original = commit(grant.authority, grant.lease, request=request, operation_id=operation_id)
        except StaleRead:
            return {"status": "stale", "problem": {"code": "project_control_basis_changed", "retryable": False}}
        except PermissionError:
            raise
        except Exception:
            return {"status": "unavailable", "problem": {"code": "project_control_outcome_unknown", "retryable": False}}
        if type(original) is not dict or original.get("operation_id") != operation_id:
            return _unavailable("project_control_original_unavailable")
        return {"status": "ready", "receipt": {"schema": "d12.project-control-receipt.v1",
            "operation_id": operation_id, "action": action, "input_digest": canonical_digest(dict(input_data)),
            "original_digest": canonical_digest(original), "original": original}}

    def read_source_correction_context_v1(self, *, session, scope, purpose, audience, source_id):
        if (audience != "owner" or purpose != "workbench_user_action"
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token
                or not session.allows(scope, "workbench.read", purpose, audience)
                or not session.allows(scope, "workbench.correct", purpose, audience)):
            return _unavailable("source_correction_policy_unavailable")
        grant = self._resolve(session, scope, purpose, audience, domains=("d06", "d07", "d12"))
        if grant is None or "workbench.correct" not in grant.capabilities:
            return _unavailable("source_correction_policy_unavailable")
        from ..graph_worker import GraphStorageWorkV3
        try:
            projection = self._coordinator.read_source_correction_context_v1(
                grant.authority, grant.lease, source_id=source_id)
        except (StaleRead, PermissionError, ValueError, RuntimeError, LookupError) as error:
            return self._source_correction_error_v3(error)
        if type(projection) is GraphStorageWorkV3:
            return projection.map_terminal_v3("issuer", self._source_correction_result_v3,
                                              self._source_correction_error_v3)
        return self._source_correction_result_v3(projection)

    @staticmethod
    def _source_correction_result_v3(projection):
        return {"status": "ready", "projection": projection}

    @staticmethod
    def _source_correction_error_v3(error):
        from ..graph_worker import GraphStorageContinuationRequiredV3
        if isinstance(error, GraphStorageContinuationRequiredV3):
            return {"status": "unavailable", "problem": {
                "code": "async_graph_worker_required", "retryable": False}}
        if isinstance(error, StaleRead):
            return {"status": "stale", "problem": {
                "code": "source_correction_basis_changed", "retryable": True}}
        if isinstance(error, PermissionError):
            raise error
        if isinstance(error, (ValueError, RuntimeError, LookupError)):
            return _unavailable("source_correction_context_unavailable")
        raise error

    def read_configuration_draft(self, *, session: AuthenticatedSession, scope: str,
                                 purpose: str, audience: str) -> Mapping[str, Any]:
        if (not session.allows(scope, "workbench.read", purpose, audience)
                or not session.allows(scope, "workbench.create", purpose, audience)):
            return _unavailable("authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None or "workbench.create" not in grant.capabilities:
            return _unavailable("authority_unavailable")
        read = getattr(self._scheme_port, "read_current_configuration_draft_v1", None)
        if not callable(read):
            return _unavailable("creator_configuration_unavailable")
        try:
            projection = read(grant.authority, grant.lease)
        except StaleRead:
            return {"status": "stale", "problem": {"code": "draft_current_basis_changed"}}
        except PermissionError:
            raise
        except (D12SchemeHold, ValueError, RuntimeError, LookupError):
            return _unavailable("creator_configuration_unavailable")
        if type(projection) is not dict or projection.get("schema") != "d12.creator-configuration.v1":
            return _unavailable("creator_configuration_unavailable")
        from ..installation_policy import AdminInstallationPolicy
        policy = self._correction_installation_policy
        projection = {**projection, "budget_ref": (
            policy.root_lease.lease_id if type(policy) is AdminInstallationPolicy
            and policy.namespace == grant.authority.namespace else None)}
        fields = set(projection["fields"])
        head_available = projection["active_head_revision"] > 0
        def allowed(capability, method):
            return (capability in grant.capabilities
                    and session.allows(scope, capability, purpose, audience)
                    and callable(getattr(self._scheme_port, method, None)))
        projection["action_permissions"] = {
            "save": allowed("workbench.create", "save_current_creator_draft_for_operation_v1"),
            "compile": allowed("workbench.compile", "compile_current_scheme_for_operation_v1"),
            "preview": head_available and fields <= {"d07.attention_policy", "d09.expression_policy"}
                and allowed("workbench.experiment", "preview_current_scheme_for_operation_v1"),
            "activate": head_available and fields == {"d09.expression_policy"}
                and allowed("workbench.activate", "adopt_current_scheme_for_operation_v1"),
        }
        from .creator_configuration_v1 import creator_field_templates_v1
        projection["field_templates"] = creator_field_templates_v1(grant.authority.namespace)
        return {"status": "ready", "projection": projection}

    def save_creator_draft(self, *, session: AuthenticatedSession, scope: str,
                          purpose: str, audience: str, operation_id: str,
                          input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        if not session.allows(scope, "workbench.create", purpose, audience):
            return _unavailable("authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None or "workbench.create" not in grant.capabilities:
            return _unavailable("authority_unavailable")
        save = getattr(self._scheme_port, "save_current_creator_draft_for_operation_v1", None)
        if not callable(save):
            return _unavailable("creator_configuration_unavailable")
        try:
            receipt = save(grant.authority, grant.lease, operation_id=operation_id, **dict(input_data))
        except StaleRead:
            return {"status": "stale", "problem": {"code": "draft_current_basis_changed"}}
        except D12SchemeHold as exc:
            return _unavailable(exc.code)
        except PermissionError:
            raise
        except LocalModuleAdmissionDeniedV1 as exc:
            return _module_disabled(exc)
        except (ValueError, RuntimeError, LookupError):
            return _unavailable("creator_draft_save_unconfirmed")
        from .creator_configuration_v1 import valid_creator_save_receipt_v1
        if not valid_creator_save_receipt_v1(receipt, operation_id, input_data):
            return _unavailable("creator_draft_save_unconfirmed")
        return {"status": "ready", "receipt": receipt}

    def read_creator_draft(self, *, session: AuthenticatedSession, scope: str,
                           draft_ref: str, purpose: str, audience: str,
                           expected_graph_revision: int | None = None
                           ) -> Mapping[str, Any]:
        """Read only the current creator draft under W01's graph fence."""
        if (not session.allows(scope, "workbench.read", purpose, audience)
                or not session.allows(scope, "workbench.create", purpose, audience)):
            return _unavailable("authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None or "workbench.create" not in grant.capabilities:
            return _unavailable("authority_unavailable")
        issuer = self._scheme_commands
        if issuer is None:
            return _unavailable("creator_draft_port_unavailable")
        try:
            frame = issuer.read_current(
                grant.authority, grant.lease, draft_ref=draft_ref,
                expected_graph_revision=expected_graph_revision,
            )
        except D12SchemeHold as exc:
            if exc.code == "stale_graph_epoch":
                return {"status": "stale", "problem": {"code": exc.code}}
            return _unavailable("creator_draft_unavailable")
        except PermissionError:
            raise
        except Exception:
            return _unavailable("creator_draft_unavailable")
        return {"status": "ready", "projection": {
            "schema": "d12.creator_draft_view.v1",
            "namespace": {"bot": frame.namespace.bot_id,
                          "persona": frame.namespace.persona_id},
            "draft_ref": frame.draft_ref,
            "draft_revision": frame.draft_revision,
            "fields": frame.draft.fields,
            "field_sources": frame.draft.field_sources,
            "active_head_ref": frame.active_head_ref,
            "active_head_revision": frame.active_head_revision,
            "graph_revision": frame.graph_revision,
            "access_epoch": frame.access_epoch,
            "delete_epoch": frame.delete_epoch,
            "access_generation": grant.authority.activation_generation,
        }}

    def read_projection(self, *, session: AuthenticatedSession, scope: str, view_type: str,
                        purpose: str, audience: str, cursor: str | None = None,
                        page_size: int = 100) -> Mapping[str, Any]:
        if not session.allows(scope, "workbench.read", purpose, audience):
            return _unavailable("authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None:
            return _unavailable("authority_unavailable")
        return self._read_projection_with_grant(
            grant, scope=scope, view_type=view_type, purpose=purpose,
            audience=audience, cursor=cursor, page_size=page_size)

    def _read_projection_with_grant(
            self, grant: CoordinatorGrant, *, scope: str, view_type: str,
            purpose: str, audience: str, cursor: str | None = None,
            page_size: int = 100) -> Mapping[str, Any]:
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
        if type(page_size) is not int or not 1 <= page_size <= 100:
            return _unavailable("invalid_page_size")
        # Context-filtered views cannot safely expose graph cursors or raw
        # coverage: hidden atoms could reveal their existence through either.
        if context_version == PROJECTION_CONTEXT_V1 and (cursor is not None or page_size != 100):
            return _unavailable("view_pagination_unavailable")
        if context_version == PROJECTION_CONTEXT_V2:
            if cursor is not None or page_size != 100:
                return _unavailable("view_pagination_unavailable")
            complete_reader = getattr(self._coordinator,
                                      "project_workbench_snapshot_v1", None)
            if not callable(complete_reader):
                return _unavailable("field_projection_unavailable")
            try:
                candidate = complete_reader(
                    grant.authority, grant.lease, view_registry=self._view_registry,
                    view_type=view_type, audience=audience, purpose=purpose,
                )
            except PermissionError:
                raise
            except Exception:
                return _unavailable("graph_query_unavailable")
            if (type(candidate) is not WorkbenchProjectionSnapshotV1
                    or candidate.namespace != grant.authority.namespace
                    or not isinstance(candidate.data, Mapping)):
                return _unavailable("invalid_field_projection")
            return {"status": "ready", "projection": {
                "view_type": view_type,
                "namespace": {"bot": candidate.namespace.bot_id,
                              "persona": candidate.namespace.persona_id},
                "data": dict(candidate.data),
                "access_generation": grant.authority.activation_generation,
            }}
        after = expected_epoch = None
        if cursor is not None:
            try:
                token = json.loads(cursor)
                if (type(token) is not dict or set(token) != {
                        "schema", "scope", "view_type", "audience", "purpose",
                        "generation", "epoch", "after"}
                        or token["schema"] != "d12.graph_page.v1"
                        or token["scope"] != scope or token["view_type"] != view_type
                        or token["audience"] != audience or token["purpose"] != purpose
                        or token["generation"] != grant.authority.activation_generation
                        or type(token["epoch"]) is not int or token["epoch"] < 0):
                    raise ValueError("cursor context mismatch")
                after = AtomKey.from_token(token["after"])
                if ((after.owner.bot, after.owner.persona) != grant.authority.namespace.as_tuple
                        or after.owner.kind != owner_kind or after.type_name not in types):
                    raise ValueError("cursor crosses view")
                expected_epoch = NamespaceEpoch(
                    grant.authority.namespace.bot_id,
                    grant.authority.namespace.persona_id, token["epoch"])
            except (TypeError, ValueError, KeyError):
                return _unavailable("invalid_view_cursor")
        try:
            page = self._coordinator.query(grant.authority, grant.lease,
                                           type_names=types, owner_kind=owner_kind,
                                           after=after, expected_epoch=expected_epoch,
                                           limit=page_size)
        except PermissionError:
            raise
        except StaleRead:
            return {"status": "stale", "problem": {"code": "view_cursor_stale"}}
        except Exception:
            return _unavailable("graph_query_unavailable")
        if not isinstance(page, GraphPage):
            return _unavailable("invalid_graph_snapshot")
        snapshot = page.snapshot
        epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
        if epoch is None:
            return _unavailable("incomplete_graph_snapshot")
        if expected_epoch is not None and epoch != expected_epoch:
            return {"status": "stale", "problem": {"code": "view_cursor_stale"}}
        if ((epoch.bot, epoch.persona) != grant.authority.namespace.as_tuple
                or any(atom.key.owner.kind != owner_kind
                       or (atom.key.owner.bot, atom.key.owner.persona)
                       != grant.authority.namespace.as_tuple
                       or atom.key.type_name not in types for atom in snapshot.atoms)):
            return _unavailable("invalid_graph_snapshot")
        if page.next_after is not None and (
                not snapshot.atoms or page.next_after != snapshot.atoms[-1].key):
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
            projection["next_cursor"] = (json.dumps({
                "schema": "d12.graph_page.v1", "scope": scope,
                "view_type": view_type, "audience": audience, "purpose": purpose,
                "generation": grant.authority.activation_generation,
                "epoch": epoch.revision, "after": page.next_after.token,
            }, sort_keys=True, separators=(",", ":")) if page.next_after is not None else None)
        return {"status": "ready", "projection": projection}

    def open_workspace(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                       audience: str) -> Mapping[str, Any]:
        if not session.allows(scope, "workbench.read", purpose, audience):
            return _unavailable("authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if grant is None:
            return _unavailable("authority_unavailable")
        return self._open_workspace_with_grant(
            grant, scope=scope, purpose=purpose, audience=audience)

    def _open_workspace_with_grant(
            self, grant: CoordinatorGrant, *, scope: str, purpose: str,
            audience: str) -> Mapping[str, Any]:
        views = self._views(grant)
        if views is None:
            return _unavailable("domain_registry_unavailable")
        entries = []
        checks = []
        for name in sorted(views):
            # The catalogue must use the same fenced graph and field projection
            # path as a view read. A one-row query cannot establish that a v2
            # view can complete its private, multi-page projection.
            read = self._read_projection_with_grant(
                grant, scope=scope, view_type=name, purpose=purpose,
                audience=audience)
            entry = {"view_type": name,
                     "status": "available" if read.get("status") == "ready" else "unavailable"}
            if entry["status"] == "available" and "snapshot_epoch" in read["projection"]:
                entry["snapshot_epoch"] = read["projection"]["snapshot_epoch"]
            entries.append(entry)
            # Diagnostic metadata comes from the same fenced read as the
            # catalogue. Never expose field values, hidden atom counts, or a
            # cursor in the workspace overview.
            check = {"view_type": name, "read_status": read.get("status", "unavailable")}
            if read.get("status") == "ready":
                projection = read.get("projection")
                coverage = projection.get("coverage") if isinstance(projection, Mapping) else None
                if isinstance(coverage, Mapping):
                    check["coverage"] = "partial" if coverage.get("truncated") is True else "complete"
                    check["snapshot_epoch"] = projection.get("snapshot_epoch")
                else:
                    check["coverage"] = "not_disclosed"
            else:
                problem = read.get("problem")
                if isinstance(problem, Mapping) and isinstance(problem.get("code"), str):
                    check["problem_code"] = problem["code"]
            checks.append(check)
        return {"status": "ready", "projection": {
            "namespace": {"bot": grant.authority.namespace.bot_id,
                          "persona": grant.authority.namespace.persona_id},
            "access_generation": grant.authority.activation_generation,
            "views": tuple(entries),
            "view_diagnostics": tuple(checks),
            "unavailable_domains": self._unavailable_domains(grant),
            "command_routes": self._command_routes(),
        }}

    def _command_routes(self) -> tuple[Mapping[str, str], ...]:
        """Describe installed server routes, without granting an operation.

        Every command still rechecks its signed Owner session and current
        domain/graph basis when submitted. A route is not a success receipt.
        """
        scheme = self._scheme_port
        routes = {
            "create_character": self._onboarding is not None and callable(
                getattr(self._coordinator, "commit_role_initialization_v2", None)),
            "bind_scene": self._onboarding is not None and callable(
                getattr(self._coordinator, "commit_scene_binding_v2", None)),
            "compile_scheme": callable(getattr(scheme, "compile_current_scheme_for_operation_v1", None))
                              and callable(getattr(scheme, "read_compilation_original_v1", None)),
            "preview_scheme": callable(getattr(scheme, "preview_current_scheme_for_operation_v1", None))
                              and callable(getattr(scheme, "read_preview_original_v1", None)),
            "activate_scheme": callable(getattr(scheme, "adopt_current_scheme_for_operation_v1", None))
                               or (self._d04_root_resource_resolver is not None
                                   and callable(getattr(
                                       self._coordinator,
                                       "commit_current_d04_authored_root_v3", None))),
            "correct_source_claim": callable(getattr(self._coordinator, "commit_source_correction_v1", None))
                                    and self._correction_installation_policy is not None
                                    and self._correction_admin_policy is not None,
            "read_source_correction_context_v1": callable(getattr(self._coordinator, "read_source_correction_context_v1", None)),
            "revoke_source_access": callable(getattr(self._coordinator, "revoke_source_access_v1", None)),
            "run_experiment": self._backend_route_installed("run_experiment")
                              or (callable(getattr(scheme, "preview_current_scheme_for_operation_v1", None))
                                  and callable(getattr(scheme, "read_preview_original_v1", None))
                                  and callable(getattr(scheme, "read_current_preview_report_v1", None))),
            "prepare_transfer": self._backend_route_installed("prepare_transfer"),
            "execute_transfer": self._backend_route_installed("execute_transfer"),
            "diagnose_and_export_support": self._backend_route_installed("diagnose_and_export_support")
                                           or self._support_export_root is not None,
            "erase_or_retire": (self._erasure_prepare is not None
                                 and self._erasure_accepted_read is not None),
            "install_or_upgrade": self._backend_route_installed("install_or_upgrade"),
            "configure_or_control": self._backend_route_installed("configure_or_control"),
            "read_installation_lifecycle": callable(getattr(self._backend_operation_port, "read_current_installation_lifecycle_v1", None)),
        }
        from .d04_initialization_v3 import ACTIONS
        routes.update({action: callable(getattr(self._coordinator, spec[0], None)) for action, spec in ACTIONS.items()})
        from .domain_operations_v1 import ACTIONS as DOMAIN_ACTIONS
        routes.update({action: callable(getattr(self._coordinator, "run_current_domain_operation_v1", None))
            for action in DOMAIN_ACTIONS})
        routes.update({action: callable(getattr(self._coordinator, action, None))
            for action in ("pause_project_v1", "resume_project_v1", "read_project_control_context_v1", "read_project_control_context_v2",
                "read_owner_project_artifact_options_v1", "read_owner_project_artifact_v1")})
        routes["d02_fixed_work_policy"] = callable(getattr(self._coordinator, "adopt_current_fixed_body_work_policy_v1", None))
        routes["d07_cognition_budget"] = callable(getattr(self._coordinator, "allocate_current_d07_cognition_budget_v1", None))
        routes["d03_context_catalogue"] = callable(getattr(self._coordinator, "adopt_current_context_catalogue_v1", None))
        routes.update({action: callable(getattr(self._coordinator, method, None)) for action, method in {
            "c04_cpu_policy": "adopt_current_c04_cpu_policy_v3", "c04_prepare": "prepare_owner_c04_trigger_v3",
            "c04_advance": "advance_current_c04_product_v3"}.items()})
        routes.update({action:self._package_maintenance_port is not None for action in
            ("read_package_maintenance","accept_package_switch","read_package_operation")})

        return tuple({"action": action, "status": (
                         "partial_route_installed" if action in {"run_experiment", "diagnose_and_export_support"}
                         and not self._backend_route_installed(action)
                         else "route_installed") if installed else "unavailable"}
                     for action, installed in sorted(routes.items()))

    def execute(self, *, session: AuthenticatedSession, action: str, scope: str,
                purpose: str, audience: str, operation_id: str,
                input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        if action in {"pause_project_v1", "resume_project_v1"}:
            return self.execute_project_control_v1(session=session, action=action, scope=scope,
                purpose=purpose, audience=audience, operation_id=operation_id, input_data=input_data)
        if action == "d03_context_catalogue":
            from .context_catalogue_v1 import execute_context_catalogue_v1
            return execute_context_catalogue_v1(self, session=session, scope=scope, purpose=purpose,
                audience=audience, operation_id=operation_id, input_data=input_data)
        from .c04_work_v3 import ACTIONS as C04_ACTIONS, execute_c04_work_v3
        if action in C04_ACTIONS:
            return execute_c04_work_v3(self, session=session, action=action, scope=scope, purpose=purpose,
                audience=audience, operation_id=operation_id, input_data=dict(input_data))
        if action == "d07_cognition_budget":
            from .d07_budget_v1 import execute_d07_budget_v1
            return execute_d07_budget_v1(self, session=session, scope=scope, purpose=purpose,
                audience=audience, operation_id=operation_id, input_data=dict(input_data))
        if action == "d02_fixed_work_policy":
            from .body_policy_v1 import execute_body_policy_v1
            return execute_body_policy_v1(self, session=session, scope=scope, purpose=purpose,
                audience=audience, operation_id=operation_id, input_data=dict(input_data))
        from .domain_operations_v1 import ACTIONS as DOMAIN_ACTIONS, execute_domain_operation_v1
        if action in DOMAIN_ACTIONS:
            return execute_domain_operation_v1(self, session=session, action=action, scope=scope,
                purpose=purpose, audience=audience, operation_id=operation_id, input_data=input_data)
        from .d04_initialization_v3 import ACTIONS, execute_initialization_v3
        if action in ACTIONS:
            return execute_initialization_v3(self, session=session, action=action, scope=scope,
                purpose=purpose, audience=audience, operation_id=operation_id, input_data=input_data)
        if (action in _BACKEND_ROUTES
                and not (action == "run_experiment" and input_data.get("experiment") == "d12.scheme_preview.v1")
                and not (action == "diagnose_and_export_support"
                         and input_data.get("question") == "view_health"
                         and input_data.get("allowed_data") == ["view_status"]
                         and input_data.get("retention_policy_ref") == "d12.local_manual_retention.v1")):
            return self._execute_backend_operation(
                session=session, action=action, scope=scope, purpose=purpose,
                audience=audience, operation_id=operation_id, input_data=input_data)
        if action == "create_character":
            return self._create_character(session=session, scope=scope, purpose=purpose,
                                          audience=audience, operation_id=operation_id,
                                          input_data=input_data)
        if action == "bind_scene":
            return self._bind_scene(session=session, scope=scope, purpose=purpose,
                                    audience=audience, operation_id=operation_id,
                                    input_data=input_data)
        if action in {"compile_scheme", "preview_scheme", "activate_scheme"}:
            return self._execute_scheme(
                session=session, action=action, scope=scope, purpose=purpose,
                audience=audience, operation_id=operation_id, input_data=input_data)
        if action == "run_experiment":
            return self._run_experiment(
                session=session, scope=scope, purpose=purpose, audience=audience,
                operation_id=operation_id, input_data=input_data)
        if action == "diagnose_and_export_support":
            return self._export_view_diagnostics(
                session=session, scope=scope, purpose=purpose, audience=audience,
                operation_id=operation_id)
        if action == "erase_or_retire":
            return self._prepare_scoped_erasure(
                session=session, scope=scope, purpose=purpose, audience=audience,
                operation_id=operation_id, input_data=input_data)
        return _unavailable("action_issuer_unavailable")

    def execute_package_maintenance(self,*,session,action,scope,purpose,audience,operation_id,input_data):
        from .package_maintenance_v2 import VIEW_SCHEMA,decode_package_status_v2,decode_package_profile_v2
        port=self._package_maintenance_port
        if port is None:return _unavailable("installed_compatible_package_lane_unavailable")
        if audience!="owner" or type(session.owner_session_request) is not OwnerSessionLoginRequestV1 or not session.owner_session_token:
            raise PermissionError("current signed Owner package session required")
        if action=="read_package_operation":
            original=input_data["operation_id"]
            if (session.package_operation_id!=original or not session.allows(scope,"workbench.package_status",purpose,audience)):
                raise PermissionError("exact operation-only package status session required")
            result=port.read_session_package_operation_v2(session=session,scope=scope,operation_id=original)
            decode_package_status_v2(result,scope=scope,operation_id=original)
            return {"status":"ready","projection":{"schema":VIEW_SCHEMA,**result}}
        if not all(session.allows(scope,c,purpose,audience) for c in ("workbench.read","workbench.maintain","workbench.control")):
            raise PermissionError("actual current Owner maintenance/control capabilities required")
        if action=="read_package_maintenance":
            view=port.read_session_package_maintenance_v2(session=session,scope=scope)
            return {"status":"ready","projection":decode_package_profile_v2(view,scope=scope)}
        if action!="accept_package_switch":raise ValueError("fixed package action required")
        try:
            result=port.accept_session_package_switch_v2(session=session,scope=scope,operation_id=operation_id,input_data=input_data)
        except PermissionError:raise
        except (RuntimeError,OSError):
            return {"status":"pending_confirmation","problem":{"code":"package_acceptance_unconfirmed",
                "operation_id":operation_id,"recovery_action":"read_package_operation"}}
        intent,result=decode_package_status_v2(result,scope=scope,operation_id=operation_id)
        return {"status":"ready" if result["stage"] in {"active","rollback_complete","abort_complete"} else "accepted",
            "receipt":{"schema":VIEW_SCHEMA,**result}}

    def read_d04_initialization_profile(self, **request):
        from .d04_initialization_v3 import read_initialization_profile_v3
        return read_initialization_profile_v3(self, **request)

    def read_installation_lifecycle(self, *, session, scope, purpose, audience):
        reader = getattr(self._backend_operation_port, "read_current_installation_lifecycle_v1", None)
        if (audience != "owner" or not callable(reader)
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1 or not session.owner_session_token
                or not all(session.allows(scope, capability, purpose, audience) for capability in ("workbench.read", "workbench.control"))):
            return _unavailable("installed_whole_host_controller_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if (grant is None or not {"workbench.read", "workbench.control"}.issubset(grant.capabilities)
                or grant.authority.issuer_domain != "d12" or "persona" not in grant.authority.owner_scope
                or grant.owner_grant_ref is None or grant.owner_grant_revision is None or grant.owner_grant_digest is None):
            return _unavailable("backend_owner_authority_unavailable")
        projection = reader(grant.authority, grant.lease)
        return {"status":"ready", "projection":projection}

    def read_backend_operation(self, *, session, scope, purpose, audience, original_ref):
        port = getattr(self._backend_operation_port, "operation_status_port", None)
        if (audience != "owner" or not session.allows(scope, "workbench.operation_status", purpose, audience)
                or session.backend_operation_ref != original_ref
                or port is None or not callable(getattr(port, "read_session_operation_status_v1", None))):
            return _unavailable("backend_status_unavailable")
        original = port.read_session_operation_status_v1(session=session, scope=scope,
            original_ref=original_ref, refresh=True)
        if (type(original) is not D12BackendOperationOriginalV1
                or original.namespace.as_tuple != tuple(scope.split("/"))):
            return _unavailable("backend_operation_original_invalid")
        return {"status": original.state, "receipt": original.to_wire()}

    def _backend_route_installed(self, action: str) -> bool:
        port = self._maintenance_port if action == "install_or_upgrade" else self._backend_operation_port
        return (callable(getattr(port, _BACKEND_ROUTES[action][0], None))
                and callable(getattr(port, "read_current_backend_operation_original_v1", None)))

    def _execute_backend_operation(
        self, *, session: AuthenticatedSession, action: str, scope: str,
        purpose: str, audience: str, operation_id: str,
        input_data: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        method, kind, capability = _BACKEND_ROUTES[action]
        if (audience != "owner" or not session.allows(scope, capability, purpose, audience)
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or not session.owner_session_token):
            return _unavailable("backend_owner_authority_unavailable")
        if action == "diagnose_and_export_support" and not session.allows(scope, "workbench.read", purpose, audience):
            return _unavailable("backend_owner_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if (grant is None or capability not in grant.capabilities
                or grant.authority.issuer_domain != "d12"
                or "persona" not in grant.authority.owner_scope
                or grant.owner_grant_ref is None
                or grant.owner_grant_revision is None
                or grant.owner_grant_digest is None):
            return _unavailable("backend_owner_authority_unavailable")
        if not self._backend_route_installed(action):
            return _unavailable(f"{kind}_port_unavailable")
        port = self._maintenance_port if action == "install_or_upgrade" else self._backend_operation_port
        digest = "sha256:" + digest_payload({
            "action": action, "scope": scope, "purpose": purpose,
            "audience": audience, "operation_id": operation_id, "input": input_data,
        })
        try:
            original = getattr(port, method)(
                grant.authority, grant.lease, operation_id=operation_id,
                request_digest=digest, input_data=dict(input_data))
            if (type(original) is not D12BackendOperationOriginalV1
                    or original.kind != kind or original.namespace != grant.authority.namespace
                    or original.operation_id != operation_id or original.request_digest != digest
                    or original.activation_generation != grant.authority.activation_generation
                    or (original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest)
                       != (grant.owner_grant_ref, grant.owner_grant_revision, grant.owner_grant_digest)
                    or port.read_current_backend_operation_original_v1(
                        grant.authority, grant.lease, original_ref=original.original_ref) != original):
                return _unavailable("backend_operation_original_invalid")
            result = original.result
            if action == "prepare_transfer" and (
                    result.mode != input_data["mode"]
                    or result.manifest_ref != input_data["manifest_ref"]):
                return _unavailable("transfer_plan_input_binding_invalid")
            if action == "execute_transfer" and (
                    original.plan_ref != input_data["plan_ref"]
                    or original.plan_digest != input_data["current_epochs"]["plan_digest"]
                    or input_data["current_epochs"]["activation_generation"]
                       != grant.authority.activation_generation):
                return _unavailable("transfer_execution_plan_binding_invalid")
            if action == "configure_or_control" and (
                    result.object_ref != input_data["object_ref"] or result.control != input_data["control"]):
                return _unavailable("control_input_binding_invalid")
            if action == "install_or_upgrade" and any(
                    getattr(result, name) != input_data[name]
                    for name in ("release_manifest_ref", "migration_plan_ref", "target_capability")):
                return _unavailable("maintenance_input_binding_invalid")
            if action == "run_experiment" and (
                    result.experiment != input_data["experiment"]
                    or result.retention_policy_ref != input_data["retention_policy_ref"]):
                return _unavailable("experiment_input_binding_invalid")
            if action == "diagnose_and_export_support" and (
                    result.allowed_data != tuple(input_data["allowed_data"])
                    or result.retention_policy_ref != input_data["retention_policy_ref"]):
                return _unavailable("support_export_input_binding_invalid")
        except D12OperationPending as exc:
            return {"status": "pending_confirmation", "problem": {
                "code": "backend_operation_continuation_required", "retryable": True,
                "operation_id": operation_id, "recovery_action": "inspect_same_operation",
                "original_ref": exc.original.original_ref,
                "stage": exc.original.result.stage}}
        except D12PrerequisiteUnavailable as exc:
            return _unavailable(exc.code)
        except PermissionError:
            raise
        except StaleRead:
            return {"status": "stale", "problem": {"code": "backend_operation_basis_changed"}}
        except LocalModuleAdmissionDeniedV1 as exc:
            return _module_disabled(exc)
        except Exception:
            # An interrupted command may already have committed. The producer
            # must resume/read by the same operation identity on the next call.
            return {"status": "pending_confirmation", "problem": {
                "code": "backend_operation_outcome_unresolved", "retryable": True,
                "operation_id": operation_id, "recovery_action": "inspect_same_operation",
            }}
        response = {"status": original.state, "receipt": original.to_wire()}
        if action == "prepare_transfer":
            preview = getattr(port, "read_current_transfer_expected_epochs_v1", None)
            if callable(preview):
                response["projection"] = preview(grant.authority, grant.lease, original_ref=original.original_ref)
        return response

    def _prepare_scoped_erasure(self, *, session: AuthenticatedSession,
                                scope: str, purpose: str, audience: str,
                                operation_id: str,
                                input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        if (self._erasure_prepare is None or self._erasure_accepted_read is None
                or purpose != "audit" or audience != "owner"
                or not session.allows(scope, "workbench.erase", purpose, audience)
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or session.owner_session_request.audience != "owner"):
            return _unavailable("erasure_authority_unavailable")
        try:
            request = D12ScopedErasureRequestV2.from_wire(input_data)
        except (TypeError, ValueError):
            return _unavailable("invalid_scoped_erasure_request")
        grant = self._resolve(session, scope, purpose, audience, domains=("d06",))
        if (grant is None or "workbench.erase" not in grant.capabilities
                or grant.authority.issuer_domain != "d12"
                or grant.authority.actor != session.actor_id
                or "persona" not in grant.authority.owner_scope
                or scope != f"{grant.authority.namespace.bot_id}/"
                             f"{grant.authority.namespace.persona_id}"):
            return _unavailable("erasure_owner_grant_unavailable")
        try:
            # The independent Authority prepare RPC performs the pinned W01
            # current-plan verification atomically with its first pending
            # original. Replays must reach that original even after W01 has
            # applied the barrier and no longer emits the pre-delete plan.
            receipt, permit = self._erasure_prepare(
                operation_id=operation_id, source_id=request.source_id,
                owner_actor_id=session.actor_id,
                owner_session_token=session.owner_session_token)
        except PermissionError:
            raise
        except Exception:
            return _unavailable("erasure_authority_prepare_unavailable")
        if (type(receipt) is not DeletionMutationReceiptV1
                or type(permit) is not FencePermitV2):
            return _unavailable("erasure_pending_receipt_invalid")
        pending = receipt.pending
        if (pending.source_phase != "absent" or pending.target_phase != "pending"
                or pending.deletion_operation_id != operation_id
                or pending.closure_roots != (request.source_id,)
                or pending.permit.namespace != permit.namespace
                or permit.operation != "delete"
                or not permit.namespace
                or permit.subject != pending.permit.subject
                or permit.operation_id != pending.permit.operation_id
                or permit.token != pending.permit.token
                or permit.revision != receipt.updated_revision
                or permit.pinned_anchor != receipt.after_anchor):
            return _unavailable("erasure_pending_receipt_invalid")
        scope_digest = deletion_scope_digest(
            pending.closure_roots, pending.deletion_epoch, pending.policy_ref)
        try:
            accepted = self._erasure_accepted_read(
                operation_id=operation_id, scope_digest=scope_digest,
                permit=permit)
        except Exception:
            accepted = None
        if type(accepted) is CurrentAcceptedErasureV1:
            if (accepted.namespace != permit.namespace
                    or accepted.deletion_operation_id != operation_id
                    or accepted.pending_receipt != receipt
                    or accepted.permit != permit
                    or accepted.scope_digest != scope_digest
                    or accepted.closure_roots != pending.closure_roots
                    or accepted.deletion_epoch != pending.deletion_epoch
                    or accepted.accepted_receipt.pending.source_phase != "pending"
                    or accepted.accepted_receipt.pending.target_phase != "accepted"):
                return _unavailable("erasure_accepted_original_invalid")
            return {"status": "accepted", "receipt": {
                "schema": "d12.scoped_erasure_accepted.v1",
                "phase": "authority_accepted", "operation_id": operation_id,
                "source_id": request.source_id,
                "deletion_epoch": accepted.deletion_epoch,
                "scope_digest": accepted.scope_digest,
                "graph_barrier_digest": accepted.graph_barrier_digest,
                "cleanup_complete": False,
            }}
        return {"status": "pending", "receipt": {
            "schema": "d12.scoped_erasure_pending.v2",
            "phase": "authority_pending", "operation_id": operation_id,
            "source_id": request.source_id,
            "deletion_epoch": pending.deletion_epoch,
            "request_digest": pending.request_digest,
        }}

    def _export_view_diagnostics(self, *, session: AuthenticatedSession,
                                 scope: str, purpose: str, audience: str,
                                 operation_id: str) -> Mapping[str, Any]:
        if (not session.allows(scope, "workbench.diagnose", purpose, audience)
                or not session.allows(scope, "workbench.read", purpose, audience)):
            return _unavailable("support_export_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if (grant is None
                or not {"workbench.read", "workbench.diagnose"}
                    .issubset(grant.capabilities)):
            return _unavailable("support_export_authority_unavailable")
        root = self._support_export_root
        if root is None:
            return _unavailable("support_export_directory_unavailable")
        current = self._open_workspace_with_grant(
            grant, scope=scope, purpose=purpose, audience=audience)
        projection = current.get("projection")
        if current.get("status") != "ready" or not isinstance(projection, Mapping):
            return _unavailable("current_view_diagnostics_unavailable")
        try:
            receipt = write_view_status_export_v1(
                root=root, operation_id=operation_id, scope=scope,
                workspace=projection)
        except (OSError, TypeError, ValueError):
            return _unavailable("support_export_write_unavailable")
        return {"status": "ready", "receipt": receipt}

    def _run_experiment(self, *, session: AuthenticatedSession, scope: str,
                        purpose: str, audience: str, operation_id: str,
                        input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        """Expose only W01's paid, immutable D07/D09 scheme comparison."""
        if not session.allows(scope, "workbench.experiment", purpose, audience):
            return _unavailable("experiment_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if (grant is None or "workbench.experiment" not in grant.capabilities
                or grant.authority.issuer_domain != "d12"
                or "persona" not in grant.authority.owner_scope):
            return _unavailable("experiment_authority_unavailable")
        port = self._scheme_port
        issue = getattr(port, "preview_current_scheme_for_operation_v1", None)
        read_certificate = getattr(port, "read_preview_original_v1", None)
        read_report = getattr(port, "read_current_preview_report_v1", None)
        if not all(callable(method) for method in (issue, read_certificate, read_report)):
            return _unavailable("experiment_report_port_unavailable")
        compiled_digest = input_data["input_refs"][0]
        try:
            original = issue(
                grant.authority, grant.lease, operation_id=operation_id,
                compiled_digest=compiled_digest,
                budget_ref=input_data["budget_ref"])
            if (type(original) is not PreviewOriginalV1
                    or original.operation_id != operation_id
                    or original.certificate.compiled_digest != compiled_digest
                    or original.certificate.sandbox_namespace == grant.authority.namespace
                    or type(original.isolated_result) is not D12IsolatedPreviewV1
                    or original.isolated_result.compiled_digest != compiled_digest
                    or original.isolated_result.sandbox_namespace
                       != original.certificate.sandbox_namespace
                    or original.isolated_result.status != "isolated_preview_only"
                    or original.isolated_result.production_revision_before
                       != original.isolated_result.production_revision_after
                    or any((original.isolated_result.external_effect_refs,
                            original.isolated_result.formal_contribution_refs,
                            original.isolated_result.production_write_refs))
                    or original.isolated_result.actual_cost_receipt_ref
                       != original.certificate.actual_cost_receipt_ref
                    or original.isolation_result_digest
                       != canonical_digest(original.isolated_result)
                    or read_certificate(
                        grant.authority, grant.lease,
                        preview_seal=original.certificate.issuer_seal)
                       != original.certificate):
                return _unavailable("experiment_isolation_original_invalid")
            report = read_report(
                grant.authority, grant.lease,
                preview_seal=original.certificate.issuer_seal)
            if (type(report) not in (D12BehaviorExperimentReportV1,
                                     D12D09PreviewReportV1)
                    or report.spec.operation_id != operation_id
                    or report.spec.namespace != grant.authority.namespace
                    or report.spec.compiled_digest != compiled_digest
                    or report.status != "isolated_behavior_only"
                    or report.hold_reason is not None
                    or report.report_digest != canonical_digest({
                        name: getattr(report, name)
                        for name in report.__dataclass_fields__
                        if name != "report_digest"
                    })):
                return _unavailable("experiment_report_original_invalid")
        except (D12SchemeHold, StaleRead):
            return {"status": "stale", "problem": {"code": "experiment_current_basis_changed"}}
        except PermissionError:
            raise
        except LocalModuleAdmissionDeniedV1 as exc:
            return _module_disabled(exc)
        except (ValueError, RuntimeError, LookupError):
            return _unavailable("experiment_current_transaction_unavailable")
        return {"status": "ready", "receipt": {
            "operation_id": operation_id, "phase": "isolated_experiment_recorded",
            "experiment": input_data["experiment"],
            "retention_policy_ref": input_data["retention_policy_ref"],
            "compiled_digest": compiled_digest,
            "preview_seal": original.certificate.issuer_seal,
            "report_digest": report.report_digest,
            "isolation_result_digest": original.isolation_result_digest,
            "actual_cost_receipt_ref": original.certificate.actual_cost_receipt_ref,
            "production_revision_unchanged": True,
            "external_effect_refs": [], "formal_contribution_refs": [],
            "production_write_refs": [],
            "coverage": list(report.coverage),
            "changed_probe_ids": list(report.changed_probe_ids),
        }}

    def _execute_scheme(self, *, session: AuthenticatedSession, action: str,
                        scope: str, purpose: str, audience: str,
                        operation_id: str, input_data: Mapping[str, Any]
                        ) -> Mapping[str, Any]:
        capability = {"compile_scheme": "workbench.compile",
                      "preview_scheme": "workbench.experiment",
                      "activate_scheme": "workbench.activate"}[action]
        if not session.allows(scope, capability, purpose, audience):
            return _unavailable("scheme_authority_unavailable")
        grant = self._resolve(session, scope, purpose, audience)
        if (grant is None or capability not in grant.capabilities
                or grant.authority.issuer_domain != "d12"
                or "persona" not in grant.authority.owner_scope):
            return _unavailable("scheme_authority_unavailable")
        port = self._scheme_port
        method_name = {
            "compile_scheme": "compile_current_scheme_for_operation_v1",
            "preview_scheme": "preview_current_scheme_for_operation_v1",
            "activate_scheme": "adopt_current_scheme_for_operation_v1",
        }[action]
        issue = getattr(port, method_name, None)
        if not callable(issue):
            return _unavailable("scheme_current_transaction_unavailable")
        try:
            if action == "compile_scheme":
                original = issue(
                    grant.authority, grant.lease, operation_id=operation_id,
                    draft_ref=input_data["draft_ref"],
                    budget_ref=input_data["budget_ref"])
                read = getattr(port, "read_compilation_original_v1", None)
                if (type(original) is not CompilationOriginalV1
                        or original.operation_id != operation_id
                        or original.compiled.namespace != grant.authority.namespace
                        or original.compiled.draft_ref != input_data["draft_ref"]
                        or not callable(read)
                        or read(grant.authority, grant.lease,
                                compiled_digest=original.compiled.compiled_digest)
                        != original.compiled):
                    return _unavailable("scheme_compilation_original_unavailable")
                return {"status": "ready", "receipt": {
                    "operation_id": operation_id, "phase": "compiled_candidate_recorded",
                    "compiled_digest": original.compiled.compiled_digest,
                    "draft_ref": original.compiled.draft_ref,
                    "draft_revision": original.compiled.draft_revision,
                    "graph_revision": original.compiled.graph_revision,
                    "source_input_digest": original.source_input_digest,
                    "budget_receipt_digest": original.budget_receipt_digest,
                }}
            if action == "preview_scheme":
                original = issue(
                    grant.authority, grant.lease, operation_id=operation_id,
                    compiled_digest=input_data["compiled_digest"],
                    budget_ref=input_data["budget_ref"])
                read = getattr(port, "read_preview_original_v1", None)
                if (type(original) is not PreviewOriginalV1
                        or original.operation_id != operation_id
                        or original.certificate.compiled_digest
                        != input_data["compiled_digest"]
                        or original.certificate.sandbox_namespace
                        == grant.authority.namespace
                        or not callable(read)
                        or read(grant.authority, grant.lease,
                                preview_seal=original.certificate.issuer_seal)
                        != original.certificate):
                    return _unavailable("scheme_preview_original_unavailable")
                return {"status": "ready", "receipt": {
                    "operation_id": operation_id, "phase": "isolated_preview_recorded",
                    "compiled_digest": original.certificate.compiled_digest,
                    "preview_seal": original.certificate.issuer_seal,
                    "isolation_result_digest": original.isolation_result_digest,
                    "actual_cost_receipt_ref":
                        original.certificate.actual_cost_receipt_ref,
                }}
            compiled = getattr(port, "read_compilation_original_v1", None)
            selection = (compiled(
                grant.authority, grant.lease,
                compiled_digest=input_data["compiled_digest"])
                if callable(compiled) else None)
            root_receipts = (() if selection is None else tuple(
                item for item in selection.domain_receipts
                if item.domain == "d04" and item.field_names == ("d04.authored_root",)))
            if len(root_receipts) == 1:
                if "preview_seal" in input_data:
                    return _unavailable("d04_root_has_no_preview_seal")
                root_grant = self._resolve(
                    session, scope, purpose, audience,
                    domains=("d04", "d11", "d12"))
                resolver = self._d04_root_resource_resolver
                resolve_resources = getattr(
                    resolver, "resolve_current_d04_root_resources", None)
                commit_root = getattr(
                    self._coordinator, "commit_current_d04_authored_root_v3", None)
                read_root = getattr(
                    self._coordinator, "read_current_d04_authored_root_v3", None)
                if (root_grant is None or "workbench.activate" not in root_grant.capabilities
                        or not callable(resolve_resources)
                        or not callable(commit_root) or not callable(read_root)):
                    return _unavailable("d04_root_installed_authority_unavailable")
                resources = resolve_resources(
                    namespace=root_grant.authority.namespace, session=session)
                if (type(resources) is not tuple or len(resources) != 2):
                    return _unavailable("d04_root_signed_budget_or_preset_unavailable")
                preset, budget_ref = resources
                adoption, root_receipt = commit_root(
                    root_grant.authority, root_grant.lease,
                    operation_id=operation_id,
                    compiled_digest=input_data["compiled_digest"],
                    parent_budget_lease_ref=budget_ref, preset=preset)
                original = read_root(
                    root_grant.authority, root_grant.lease,
                    operation_id=operation_id)
                if (type(adoption) is not D12SchemeAdoptionReceiptV1
                        or adoption.operation_id != operation_id
                        or adoption.compiled_digest != input_data["compiled_digest"]
                        or root_receipt.status != "committed"
                        or original is None
                        or original.operation_id != operation_id
                        or original.graph_receipt_digest != canonical_digest({
                            "status": root_receipt.status,
                            "revisions": [[item.key.token, item.revision] for item in root_receipt.revisions],
                            "invalidated": [[item.key.token, item.revision] for item in root_receipt.invalidated],
                            "epoch": asdict(root_receipt.epoch)})):
                    return _unavailable("d04_root_original_or_receipt_unavailable")
                return {"status": "ready", "receipt": {
                    "operation_id": operation_id,
                    "phase": "scheme_adopted",
                    "compiled_digest": adoption.compiled_digest,
                    "previous_head_revision": adoption.previous_head_revision,
                    "active_head_ref": adoption.active_head_ref,
                    "active_head_revision": adoption.active_head_revision,
                    "graph_revision": root_receipt.epoch.revision,
                    "authored_root_original_digest": original.original_digest,
                }}
            if "preview_seal" not in input_data:
                return _unavailable("scheme_preview_seal_required")
            receipt = issue(
                grant.authority, grant.lease, operation_id=operation_id,
                compiled_digest=input_data["compiled_digest"],
                preview_seal=input_data["preview_seal"])
            if (type(receipt) is not D12SchemeAdoptionReceiptV1
                    or receipt.operation_id != operation_id
                    or receipt.namespace != grant.authority.namespace
                    or receipt.compiled_digest != input_data["compiled_digest"]
                    or receipt.status != "coordinator_committed_scheme"):
                return _unavailable("scheme_adoption_receipt_unavailable")
            return {"status": "ready", "receipt": {
                "operation_id": operation_id, "phase": "scheme_adopted",
                "compiled_digest": receipt.compiled_digest,
                "previous_head_revision": receipt.previous_head_revision,
                "active_head_ref": receipt.active_head_ref,
                "active_head_revision": receipt.active_head_revision,
                "graph_revision": receipt.graph_revision,
            }}
        except (D12SchemeHold, StaleRead):
            return {"status": "stale", "problem": {"code": "scheme_current_basis_changed"}}
        except PermissionError:
            raise
        except LocalModuleAdmissionDeniedV1 as exc:
            return _module_disabled(exc)
        except (ValueError, RuntimeError, LookupError):
            return _unavailable("scheme_current_transaction_unavailable")

    def correct_source_claim(self, *, session: AuthenticatedSession, scope: str,
                             purpose: str, audience: str,
                             request: SourceCorrectionRequestV1) -> Mapping[str, Any]:
        """Cross only a dedicated W01 correction commit port, never generic execute.

        The W01 method must recheck the signed Owner session, durable graph
        grant, source access and deletion epochs in its commit transaction.
        The full Workbench command digest is checked here before W01 receives
        it; W01 checks it again against its own current graph transaction.
        """
        if (type(request) is not SourceCorrectionRequestV1
                or scope != f"{request.namespace.bot_id}/{request.namespace.persona_id}"
                or not session.allows(scope, "workbench.correct", purpose, audience)):
            return _unavailable("source_correction_policy_unavailable")
        correction_input = {
            "schema": request.schema,
            "correction_kind": "source_claim",
            "statement": request.statement,
            "source_refs": list(request.source_refs),
            "target_refs": list(request.target_refs),
            "access_epoch": request.access_epoch,
            "deletion_epoch": request.deletion_epoch,
        }
        if request.impact_preview_ref is not None:
            correction_input["impact_preview_ref"] = request.impact_preview_ref
        expected_digest = "sha256:" + digest_payload({
            "action": "correct_or_edit", "scope": scope,
            "purpose": purpose, "audience": audience,
            "operation_id": request.operation_id, "input": correction_input,
        })
        if request.request_digest != expected_digest:
            return _unavailable("source_correction_request_digest_mismatch")
        login = session.owner_session_request
        if (type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(login) is not OwnerSessionLoginRequestV1
                or login.audience != audience):
            return _unavailable("signed_owner_session_unavailable")
        commit = getattr(self._coordinator, "commit_source_correction_v1", None)
        if not callable(commit):
            return _unavailable("source_correction_commit_unavailable")
        try:
            result = commit(
                request=request, actor_id=session.actor_id,
                principal=login.principal,
                purpose=purpose, audience=audience,
                installation_policy=self._correction_installation_policy,
                admin_policy=self._correction_admin_policy,
                owner_session_token=session.owner_session_token,
                owner_session_request=login,
            )
        except PermissionError:
            raise
        except Exception:
            # A failed response is not proof that the transaction did not commit.
            # A retry must keep the same operation ID so W01 can replay its receipt.
            return {"status": "unavailable", "problem": {
                "code": "source_correction_outcome_unknown", "retryable": False,
            }}
        if (type(result) is not SourceCorrectionCommitReceiptV1
                or result.namespace != request.namespace
                or result.operation_id != request.operation_id
                or result.request_digest != request.request_digest
                or result.source_refs != request.source_refs
                or result.invalidated_target_refs != request.target_refs
                or result.access_epoch != request.access_epoch
                or result.deletion_epoch != request.deletion_epoch):
            return _unavailable("source_correction_receipt_invalid")
        return {"status": "ready", "receipt": {
            "schema": result.schema, "phase": result.phase,
            "operation_id": result.operation_id,
            "request_digest": result.request_digest,
            "correction_source_ref": result.correction_source_ref,
            "source_refs": list(result.source_refs),
            "invalidated_target_refs": list(result.invalidated_target_refs),
            "reevaluation_outbox_ref": result.reevaluation_outbox_ref,
            "audit_event_ref": result.audit_event_ref,
            "graph_revision": result.graph_revision,
            "access_epoch": result.access_epoch,
            "deletion_epoch": result.deletion_epoch,
        }}

    def revoke_source_access(self, *, session: AuthenticatedSession, scope: str,
                             purpose: str, audience: str, operation_id: str,
                             input_data: Mapping[str, Any],
                             request_digest: str) -> Mapping[str, Any]:
        """Submit a narrow D06 access revocation through W01's Owner lease."""
        from ..domains.d06.source_access_revocation import SourceAccessRevocationRequest

        if (purpose != "audit" or audience != "owner"
                or not session.allows(scope, "workbench.correct", purpose, audience)
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or session.owner_session_request.audience != audience):
            return _unavailable("signed_owner_session_unavailable")
        grant = self._resolve(session, scope, purpose, audience,
                              domains=("d06", "d11"))
        if grant is None or "workbench.correct" not in grant.capabilities:
            return _unavailable("authority_unavailable")
        authority = grant.authority
        if (authority.issuer_domain != "d12" or authority.purpose != "audit"
                or authority.audience != ("owner",)
                or "persona" not in authority.owner_scope
                or authority.actor != session.actor_id
                or scope != f"{authority.namespace.bot_id}/{authority.namespace.persona_id}"):
            return _unavailable("authority_unavailable")
        try:
            request = SourceAccessRevocationRequest(
                source_id=input_data["source_id"], owner_actor=session.actor_id,
                request_id=operation_id, recorded_at=input_data["recorded_at"],
            )
        except (KeyError, TypeError, ValueError):
            return _unavailable("invalid_source_access_revocation")
        expected_digest = "sha256:" + digest_payload({
            "action": "correct_or_edit", "scope": scope,
            "purpose": purpose, "audience": audience,
            "operation_id": operation_id, "input": dict(input_data),
        })
        if request_digest != expected_digest:
            return _unavailable("source_access_revocation_digest_mismatch")
        commit = getattr(self._coordinator, "revoke_source_access_v1", None)
        if not callable(commit):
            return _unavailable("source_access_revocation_port_unavailable")
        try:
            result = commit(authority, grant.lease, request)
        except PermissionError:
            raise
        except Exception:
            return {"status": "unavailable", "problem": {
                "code": "source_access_revocation_outcome_unknown", "retryable": False,
            }}
        if (type(result) is not SourceAccessRevocationReceiptV1
                or result.namespace != authority.namespace
                or result.source_id != request.source_id
                or not result.operation_id
                or type(result.graph_revision) is not int or result.graph_revision < 1
                or type(result.access_epoch) is not int or result.access_epoch < 1
                or type(result.delete_epoch) is not int or result.delete_epoch < 0):
            return _unavailable("source_access_revocation_receipt_invalid")
        return {"status": "ready", "receipt": {
            "schema": "d12.source_access_revocation_receipt.v1",
            "phase": "source_access_revoked", "operation_id": operation_id,
            "coordinator_operation_id": result.operation_id,
            "request_digest": request_digest,
            "coordinator_request_digest": result.request_digest,
            "source_id": result.source_id,
            "source_revision": result.source_revision,
            "access_revision": result.access_revision,
            "graph_revision": result.graph_revision,
            "graph_epoch": result.graph_epoch,
            "access_epoch": result.access_epoch, "delete_epoch": result.delete_epoch,
        }}

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
        digest = "sha256:" + digest_payload({
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
        digest = "sha256:" + digest_payload({
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
        if version not in (None, PROJECTION_CONTEXT_V1, PROJECTION_CONTEXT_V2):
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
                 audience: str, *, domains: tuple[str, ...] | None = None
                 ) -> CoordinatorGrant | None:
        if domains is None:
            grant = self._grants.resolve(session=session, scope=scope, purpose=purpose,
                                         audience=audience)
        else:
            resolver = getattr(self._grants, "resolve_for_domains", None)
            if not callable(resolver):
                return None
            grant = resolver(session=session, scope=scope, purpose=purpose,
                             audience=audience, domains=domains)
        if not isinstance(grant, CoordinatorGrant):
            return None
        # The resolved authority is authoritative; reject a resolver that tried
        # to bind this browser scope to a different session/purpose/audience.
        if (grant.scope != scope or grant.authority.actor != session.actor_id
                or grant.authority.purpose != purpose
                or audience not in grant.authority.audience
                or scope != (f"{grant.authority.namespace.bot_id}/"
                             f"{grant.authority.namespace.persona_id}")):
            return None
        return grant


def _module_disabled(exc):
    modules = ", ".join(value.upper() for value in exc.disabled_modules)
    return {"status": "unavailable", "problem": {"code": "local_module_disabled", "retryable": False,
        "message": f"本机模块 {modules} 已关闭新工作。请在插件配置页开启并重载后再创建新操作。"}}


def _unavailable(code: str) -> Mapping[str, Any]:
    return {"status": "unavailable", "problem": {"code": code, "retryable": True}}


__all__ = ("CoordinatorGrant", "GrantResolver", "DomainViewRegistry", "GraphWorkbenchIssuer")
