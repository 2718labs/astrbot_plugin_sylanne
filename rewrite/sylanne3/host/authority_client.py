from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Protocol

from .authority_transport_contract import (
    AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL, REQUIRED_AUTHORITY_CAPABILITIES,
    PublisherPackageIdentity, AuthorityProvisioningRequest, AuthorityHandshake,
    AuthorityEnrollmentGrant, AuthorityCapabilityGrant,
)
from ..authority_service.v2_contract import DeletionMutationReceiptV1, FencePermitV2
from ..authority_service.current_accepted_erasure_read import CurrentAcceptedErasureV1
from ..authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1,
)
from ..authority_service.internal_work_contract import (
    AuthorityInternalWorkVerifiedReceiptV1, InternalWorkJournalInspectionV1,
)
from ..authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelAdmissionV2, HostObservedModelCompletionV2, ModelTerminalReceiptV2,
)
from ..authority_service.v2_model_result_read_contract import (
    ModelResultReadRequestV1, ModelResultReadV1,
)
from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
)
from ..authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
)
from ..authority_service.v2_context_reply_result_contract import (
    ContextReplyResultReadRequestV1, ContextReplyPaidResultReadV2,
)
from ..authority_service.v2_natural_generation_output_contract import (
    NaturalGenerationOriginalOutputV2, NaturalGenerationOutputReadRequestV2,
)
from ..authority_service.v2_natural_generation_content_contract import (
    NaturalGenerationContentReadRequestV2, NaturalGenerationCurrentContentV2,
)
from ..authority_service.v2_natural_review_output_contract import (
    NaturalReviewOriginalOutputV2, NaturalReviewOutputReadRequestV2,
)
from ..authority_service.v2_natural_paid_review_contract import (
    NaturalPaidReviewCurrentReadRequestV2, NaturalPaidReviewCurrentReadV2,
)
from ..authority_service.v2_self_identity_contract import (
    AuthorityCurrentSelfIdentityV1, SelfIdentityCurrentRequestV1,
)
from ..authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1, WorkerResultReadFactV1,
    WorkerResultReadFactRequestV2, WorkerResultReadFactV2,
)
from ..authority_service.v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from ..model_broker.broker import ModelCallRequest
from ..installation_policy import AdminInstallationPolicy
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime.c02_cost_settlement import C02OriginalIntentLookupV1
from ..runtime.graph_write_attempt import domain_bundle_write_attempt_id_v1
from ..runtime_contracts import InstallationGrantV2


_PROFILE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AuthoritySelection:
    """An administrator-created profile name, never authority credentials."""

    profile_id: str = "default"

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or not _PROFILE.fullmatch(self.profile_id):
            raise ValueError("authority_profile must be a bounded profile identifier")


@dataclass(frozen=True)
class AuthorityClientStatus:
    state: str
    authority_id: str = ""
    detail: str = ""


class AuthorityTransport(Protocol):
    """Port implemented only by an administrator-installed companion client.

    The implementation must authenticate a remote service with mutually
    authenticated transport, or an OS-protected local service identity. It must
    bind the handshake and provisioning response to the same authenticated
    channel. Content adapters must hold begin_content_operation through
    end_content_operation; a point-in-time check cannot implement the fence.
    Journal adapters must verify the current independent chain head even when
    the caller's previous and current heads are equal. AstrBot chat
    configuration is outside this trust boundary.
    """

    async def handshake(
        self, request: AuthorityProvisioningRequest, *, protocol: str = AUTHORITY_PROTOCOL,
    ) -> AuthorityHandshake: ...

    async def capability_grant(
        self,
        request: AuthorityProvisioningRequest,
        handshake: AuthorityHandshake,
    ) -> AuthorityEnrollmentGrant | AuthorityCapabilityGrant: ...

    async def installation_grant_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
    ) -> InstallationGrantV2: ...

    async def migration_command_v2(self, request: AuthorityProvisioningRequest,
                                   handshake: AuthorityHandshake,
                                   command: dict[str, object]) -> object: ...

    async def model_capacity_reconcile_v1(self, request, handshake, grant, *, namespace,
                                           holder, expected_anchor, draft=None,
                                           close_prepared=False): ...

    async def v2_get_content_fence_operation(self,request,handshake,*,namespace,operation_id): ...

    async def v2_current_anchor(self,request,handshake,namespace): ...

    async def model_prepare_fenced_v1(self, request, handshake, grant, *, namespace,
                                      holder, draft, expected_anchor, _on_dispatch=None): ...

    async def model_admit_dispatch_once_v1(self, request, handshake, grant, *, namespace,
                                           holder, intent, expected_anchor,
                                           model_request): ...

    async def model_recover_fenced_v1(self, request, handshake, grant, *, namespace,
                                     holder, intent): ...

    async def model_admit_dispatch_once_v2(self, request, handshake, grant, *, namespace,
                                           holder, intent, expected_anchor, model_request,
                                           host_incarnation, _on_dispatch=None): ...

    async def model_complete_observed_v2(self, request, handshake, grant, *, namespace,
                                         holder, intent, expected_anchor, admission,
                                         report): ...

    async def qualify_current_life_numeric_model_candidate_v3(
        self,request,handshake,grant,*,namespace,holder,original_intent,original_permit,case,candidate_intent,
    ): ...

    async def model_terminal_fact_v2(self, request, handshake, grant, *, namespace,
                                     holder, intent): ...

    async def model_original_intent_lookup_v1(self, request, handshake, grant, *,
                                              lookup: C02OriginalIntentLookupV1): ...

    async def model_result_read_v1(self, request, handshake, grant, *, namespace,
                                   read_request, owner_session_token): ...

    async def model_result_read_recover_finish_v1(self, request, handshake, grant,
                                                    *, namespace, read_request): ...

    async def artifact_draft_model_result_read_v1(self, request, handshake, grant, *, namespace, read_request): ...

    async def artifact_draft_model_result_read_v2(self, request, handshake, grant, *, namespace, read_request): ...

    async def worker_model_result_read_v1(self, request, handshake, grant,
                                           *, namespace, read_request): ...

    async def worker_model_result_select_attempt_v1(
        self, request, handshake, grant, *, namespace, first_request): ...

    async def worker_model_result_recover_finish_v1(self, request, handshake, grant,
                                                    *, namespace, read_request): ...

    async def reply_worker_model_result_select_attempt_v1(
        self, request, handshake, grant, *, namespace, first_request): ...

    async def reply_worker_model_result_read_v1(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def reply_worker_model_result_recover_finish_v1(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def context_reply_result_read_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def context_reply_result_recover_finish_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def d04_appraisal_result_read_v3(self, request, handshake, grant, *, namespace, read_request): ...

    async def d04_appraisal_result_recover_finish_v3(self, request, handshake, grant, *, namespace, read_request): ...

    async def natural_generation_output_select_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def natural_generation_content_read_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def natural_generation_output_recover_finish_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def natural_review_output_select_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def natural_review_output_recover_finish_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def natural_paid_review_current_read_v2(
        self, request, handshake, grant, *, namespace, read_request): ...

    async def self_identity_current_v1(self, request, handshake, grant,
                                       *, namespace, current_request): ...

    async def worker_result_read_fact_v1(self, request, handshake, grant,
                                         *, namespace, fact_request): ...

    async def worker_result_read_fact_v2(self, request, handshake, grant,
                                         *, namespace, fact_request): ...

    async def v2_get_pending_deletion_for_graph_write(
        self, request, handshake, *, namespace, deletion_operation_id, permit,
    ): ...

    async def v2_read_current_accepted_erasure_v1(
        self, request, handshake, *, namespace, deletion_operation_id,
        scope_digest, permit,
    ): ...

    async def v2_get_content_fence_operation(
        self, request, handshake, *, namespace, operation_id,
    ): ...

    async def c04_terminal_verify_v1(
        self, request, handshake, grant, *, namespace, proof,
    ): ...

    async def c04_execute_v2(
        self, request, handshake, grant, *, namespace, binding,
    ): ...

    async def c04_inspect_v2(
        self, request, handshake, grant, *, namespace, binding,
    ): ...

    async def c04_execute_v3(
        self, request, handshake, grant, *, namespace, binding,
    ): ...

    async def c04_inspect_v3(
        self, request, handshake, grant, *, namespace, binding,
    ): ...


class AuthorityClient:
    """Fail-closed enrollment client for the separately installed authority."""

    def __init__(
        self,
        selection: AuthoritySelection,
        *,
        package_root: Path,
        data_dir: Path,
        transport: AuthorityTransport | None = None,
    ) -> None:
        if not isinstance(selection, AuthoritySelection):
            raise TypeError("selection must be AuthoritySelection")
        self._selection = selection
        self._package_root = Path(package_root)
        self._data_dir = Path(data_dir)
        if not self._package_root.is_absolute() or not self._data_dir.is_absolute():
            raise ValueError("authority client paths must be absolute")
        self._transport = transport
        self._request: AuthorityProvisioningRequest | None = None
        self._handshake: AuthorityHandshake | None = None
        self._v2_request: AuthorityProvisioningRequest | None = None
        self._v2_handshake: AuthorityHandshake | None = None

    def _build_request(self) -> AuthorityProvisioningRequest:
        manifest_path = self._package_root / "release-manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise FileNotFoundError("publisher release-manifest.json is unavailable or unsafe")
        identity = PublisherPackageIdentity(hashlib.sha256(manifest_path.read_bytes()).hexdigest())
        return AuthorityProvisioningRequest(
            protocol=AUTHORITY_PROTOCOL,
            profile_id=self._selection.profile_id,
            plugin_name="astrbot_plugin_sylanne",
            host_api_version="4.28.1",
            package_root=self._package_root,
            data_dir=self._data_dir,
            publisher_package=identity,
        )

    async def status(self) -> AuthorityClientStatus:
        if self._transport is None:
            return AuthorityClientStatus(
                "enrollment_required",
                detail="install and pair a Sylanne Authority companion service",
            )
        try:
            request = await asyncio.to_thread(self._build_request)
            handshake = await self._transport.handshake(request)
        except Exception:
            return AuthorityClientStatus("unavailable", detail="authority handshake failed")
        if not isinstance(handshake, AuthorityHandshake) or not handshake.valid_pairing():
            return AuthorityClientStatus(
                "enrollment_required",
                detail="authority profile is not paired or publisher package is not trusted",
            )
        self._request = request
        self._handshake = handshake
        return AuthorityClientStatus("paired", handshake.installation_authority_id)

    async def status_v2(self) -> AuthorityClientStatus:
        """Pair this installation using the v2 protocol on its authenticated channel."""
        self._v2_request = None
        self._v2_handshake = None
        if self._transport is None:
            return AuthorityClientStatus(
                "enrollment_required",
                detail="install and pair a Sylanne Authority companion service",
            )
        try:
            request = await asyncio.to_thread(self._build_request)
            handshake = await self._transport.handshake(
                request, protocol=AUTHORITY_V2_PROTOCOL,
            )
        except Exception:
            return AuthorityClientStatus("unavailable", detail="authority v2 handshake failed")
        if not isinstance(handshake, AuthorityHandshake) or not handshake.valid_pairing():
            return AuthorityClientStatus(
                "enrollment_required",
                detail="authority profile is not paired or publisher package is not trusted",
            )
        self._v2_request = request
        self._v2_handshake = handshake
        return AuthorityClientStatus("paired", handshake.installation_authority_id)

    async def installation_grant_v2(self) -> InstallationGrantV2 | None:
        """Return v2 installation facts only; no namespace activation is implied."""
        if self._transport is None:
            return None
        if self._v2_request is None or self._v2_handshake is None:
            if (await self.status_v2()).state != "paired":
                return None
        assert self._v2_request is not None and self._v2_handshake is not None
        try:
            current_request = await asyncio.to_thread(self._build_request)
            if current_request != self._v2_request:
                return None
            grant = await self._transport.installation_grant_v2(
                self._v2_request, self._v2_handshake,
            )
        except Exception:
            return None
        if not isinstance(grant, InstallationGrantV2):
            return None
        return grant if (
            grant.authority_id == self._v2_handshake.installation_authority_id
            and grant.subject == self._v2_handshake.installation_identity_ref
            and grant.manifest_digest == self._v2_request.publisher_package.manifest_sha256
            and grant.channel_binding_sha256 == self._v2_handshake.channel_binding_sha256
        ) else None

    async def migration_command_v2(self, command: dict[str, object]) -> object:
        """Use the paired management channel; server-installed facts authorize stages."""
        from ..authority_service.v2_migration_rpc import SCHEMA as MIGRATION_RPC_SCHEMA
        if (type(command) is not dict or command.get("schema") != MIGRATION_RPC_SCHEMA
                or self._transport is None):
            raise RuntimeError("authority migration command is invalid")
        if self._v2_request is None or self._v2_handshake is None:
            if (await self.status_v2()).state != "paired":
                raise RuntimeError("authority migration channel is unavailable")
        assert self._v2_request is not None and self._v2_handshake is not None
        current = await asyncio.to_thread(self._build_request)
        if current != self._v2_request or not self._v2_handshake.valid_pairing():
            raise RuntimeError("authority migration channel has changed")
        return await self._transport.migration_command_v2(
            self._v2_request, self._v2_handshake, command,
        )

    async def pending_deletion_for_graph_write_v2(
        self, bundle, grant: InstallationGrantV2, *,
        deletion_operation_id: str, permit: FencePermitV2,
    ) -> DeletionMutationReceiptV1:
        """Read the current original through this installation's paired channel."""
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(permit) is not FencePermitV2 or permit.operation != "delete"
                or permit.namespace != policy.authority_namespace
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("deletion graph read differs from installation")
        return await self._transport.v2_get_pending_deletion_for_graph_write(
            request, handshake, namespace=policy.authority_namespace,
            deletion_operation_id=deletion_operation_id, permit=permit)

    async def current_accepted_erasure_v1(
        self, bundle, grant: InstallationGrantV2, *,
        deletion_operation_id: str, scope_digest: str, permit: FencePermitV2,
    ) -> CurrentAcceptedErasureV1:
        """Read Authority-current acceptance; caller receipts are never inputs."""
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(permit) is not FencePermitV2 or permit.operation != "delete"
                or permit.namespace != policy.authority_namespace
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("accepted erasure read differs from installed namespace")
        current_permit, state = await self._transport.v2_get_content_fence_operation(
            request, handshake, namespace=policy.authority_namespace,
            operation_id=permit.operation_id)
        if (state != "active" or type(current_permit) is not FencePermitV2
                or current_permit.operation != "delete"
                or current_permit.namespace != permit.namespace
                or current_permit.operation_id != permit.operation_id
                or current_permit.token != permit.token
                or current_permit.subject != permit.subject
                or current_permit.holder != permit.holder
                or current_permit.authority_id != permit.authority_id
                or current_permit.generation != permit.generation
                or current_permit.revision < permit.revision):
            raise RuntimeError("current live delete fence differs from pending original")
        return await self._transport.v2_read_current_accepted_erasure_v1(
            request, handshake, namespace=policy.authority_namespace,
            deletion_operation_id=deletion_operation_id,
            scope_digest=scope_digest, permit=current_permit)

    async def prepare_current_erasure_v1(
        self, bundle, grant: InstallationGrantV2, *, operation_id: str,
        source_id: str, owner_actor_id: str, owner_session_token: str,
    ) -> tuple[DeletionMutationReceiptV1, FencePermitV2]:
        """Ask the paired Authority to durably prepare one Owner-scoped D06 deletion."""
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.v2_prepare_current_erasure_v1(
            request, handshake, namespace=policy.authority_namespace,
            operation_id=operation_id, source_id=source_id,
            owner_actor_id=owner_actor_id,
            owner_session_token=owner_session_token)

    async def c04_terminal_verify_v1(self,bundle,grant: InstallationGrantV2,*,proof: InternalWorkTerminalProofV1):
        if type(proof) is not InternalWorkTerminalProofV1:
            raise RuntimeError("C04 actual terminal proof required")
        return await self._execute_c04_original_rpc_v3(bundle,grant,method="c04_terminal_verify_v1",proof=proof)

    async def c04_execute_v2(self, bundle, grant: InstallationGrantV2, *,
                             binding: InternalWorkBindingV1
                             ) -> InternalWorkJournalInspectionV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if type(binding) is not InternalWorkBindingV1 or binding.namespace != policy.authority_namespace:
            raise RuntimeError("C04 execution differs from installed namespace")
        return await self._transport.c04_execute_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            binding=binding)

    async def c04_inspect_v2(self, bundle, grant: InstallationGrantV2, *,
                             binding: InternalWorkBindingV1
                             ) -> InternalWorkJournalInspectionV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if type(binding) is not InternalWorkBindingV1 or binding.namespace != policy.authority_namespace:
            raise RuntimeError("C04 inspection differs from installed namespace")
        return await self._transport.c04_inspect_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            binding=binding)

    async def c04_execute_v3(self, bundle, grant: InstallationGrantV2, *, binding: InternalWorkBindingV1):
        if type(binding) is not InternalWorkBindingV1 or binding.algorithm_ref != "d06.association_activation.v3":
            raise RuntimeError("C04 V3 execution differs from installed binding")
        return await self._execute_c04_original_rpc_v3(bundle,grant,method="c04_execute_v3",binding=binding)

    async def c04_inspect_v3(self, bundle, grant: InstallationGrantV2, *, binding: InternalWorkBindingV1):
        if type(binding) is not InternalWorkBindingV1 or binding.algorithm_ref != "d06.association_activation.v3":
            raise RuntimeError("C04 V3 inspection differs from installed binding")
        return await self._execute_c04_original_rpc_v3(bundle,grant,method="c04_inspect_v3",binding=binding)

    async def c04_execute_v4(self, bundle, grant: InstallationGrantV2, *, binding: InternalWorkBindingV1):
        if type(binding) is not InternalWorkBindingV1 or binding.algorithm_ref != "d06.association_activation.direct_seed.v4":
            raise RuntimeError("C04 V4 execution differs from installed binding")
        return await self._execute_c04_original_rpc_v3(bundle,grant,method="c04_execute_v4",binding=binding)

    async def c04_inspect_v4(self, bundle, grant: InstallationGrantV2, *, binding: InternalWorkBindingV1):
        if type(binding) is not InternalWorkBindingV1 or binding.algorithm_ref != "d06.association_activation.direct_seed.v4":
            raise RuntimeError("C04 V4 inspection differs from installed binding")
        return await self._execute_c04_original_rpc_v3(bundle,grant,method="c04_inspect_v4",binding=binding)

    async def _execute_c04_original_rpc_v3(self,bundle,grant,*,method,**originals):
        """Fresh exact installed channel, preserving each once-only C04 original."""
        from dataclasses import asdict
        from .mtls_transport import MtlsAuthorityTransport, AuthorityChannelUnavailable
        if method not in {"c04_execute_v3","c04_inspect_v3","c04_execute_v4","c04_inspect_v4","c04_terminal_verify_v1","internal_accounting_v1"}:
            raise ValueError("unregistered fixed C04 original RPC")
        request,policy=await self._d04_installation_context_v3(bundle,grant)
        for attempt in range(2):
            transport=MtlsAuthorityTransport({bundle.tls_profile.profile_id:bundle.tls_profile})
            try:
                handshake=await transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
                current=await transport.installation_grant_v2(request,handshake)
                before=asdict(grant);after=asdict(current)
                before.pop("channel_binding_sha256");after.pop("channel_binding_sha256")
                if before!=after:raise RuntimeError("C04 reconnected installation identity changed")
                return await getattr(transport,method)(request,handshake,current,
                    namespace=policy.authority_namespace,**originals)
            except AuthorityChannelUnavailable:
                if attempt or method in {"c04_execute_v3","c04_execute_v4"}:raise
            finally:await transport.close()
        raise RuntimeError("C04 original RPC remains unresolved")

    async def _d04_installation_context_v3(self,bundle,grant):
        from .authority_profile import AdminInstallationBundle
        from .mtls_transport import MtlsAuthorityTransport
        if (type(bundle) is not AdminInstallationBundle or type(grant) is not InstallationGrantV2
                or type(self._transport) is not MtlsAuthorityTransport):raise RuntimeError("actual installed D04 pairing required")
        request=await asyncio.to_thread(self._build_request);policy=bundle.installation_policy
        if (type(policy) is not AdminInstallationPolicy or self._transport.profile_for(request.profile_id)!=bundle.tls_profile
                or (grant.authority_id,grant.installation_id,grant.manifest_digest,grant.administrator_holder)!=
                (policy.expected_authority_id,policy.installation_id,policy.manifest_digest,policy.administrator_holder)
                or request.publisher_package.manifest_sha256!=grant.manifest_digest
                or bundle.tls_profile.expected_authority_id!=grant.authority_id):raise RuntimeError("D04 administrator/package identity changed")
        return request,policy

    async def _d04_numeric_v3(self, bundle, grant, *, binding, method, **originals):
        from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3
        request, policy = await self._d04_installation_context_v3(bundle, grant)
        if (type(binding) is not D04NumericBindingV3
                or binding.namespace != policy.namespace
                or binding.authority_namespace != policy.authority_namespace
                or binding.installation_id != policy.installation_id):
            raise RuntimeError("D04 numeric identity differs from installation")
        return await self._execute_d04_rpc_v3(bundle,grant,binding=binding,method=method,transport_method="d04_numeric_v3",**originals)

    async def d04_numeric_bridge_v3(self,bundle,grant,*,binding,method,**originals):
        from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3
        request,policy=await self._d04_installation_context_v3(bundle,grant)
        if (type(binding) is not D04NumericBindingV3 or binding.namespace!=policy.namespace
                or binding.authority_namespace!=policy.authority_namespace or binding.installation_id!=policy.installation_id):
            raise RuntimeError("numeric bridge identity differs from installed bundle")
        return await self._execute_d04_rpc_v3(bundle,grant,binding=binding,method=method,transport_method="d04_numeric_bridge_v3",**originals)

    async def d04_root_v3(self,bundle,grant,*,binding,method,**originals):
        from ..authority_service.d04_root_execution_contract_v3 import D04RootExecutionBindingV3
        policy=bundle.installation_policy
        if (type(binding) is not D04RootExecutionBindingV3 or binding.namespace!=policy.namespace
                or binding.authority_namespace!=policy.authority_namespace or binding.installation_id!=policy.installation_id):raise RuntimeError("root original identity differs from installed bundle")
        return await self._execute_d04_rpc_v3(bundle,grant,binding=binding,method=method,transport_method="d04_root_v3",**originals)

    async def _execute_d04_rpc_v3(self,bundle,grant,*,binding,method,transport_method,**originals):
        """Reauthenticate installed originals after long CPU on a fresh channel.

        A separate bounded channel avoids invalidating unrelated live Owner or
        Graph sessions. Retries keep the identical binding, claim and measured
        original; a first-claim ACK loss is inspection-only at the caller.
        """
        from dataclasses import asdict
        from .mtls_transport import MtlsAuthorityTransport,AuthorityChannelUnavailable
        request,policy=await self._d04_installation_context_v3(bundle,grant)
        if type(self._transport) is not MtlsAuthorityTransport:raise RuntimeError("installed D04 mTLS transport required")
        for attempt in range(2):
            transport=MtlsAuthorityTransport({bundle.tls_profile.profile_id:bundle.tls_profile})
            try:
                handshake=await transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
                current=await transport.installation_grant_v2(request,handshake)
                before=asdict(grant);after=asdict(current)
                before.pop("channel_binding_sha256");after.pop("channel_binding_sha256")
                if before!=after:raise RuntimeError("D04 reconnected installed identity changed")
                return await getattr(transport,transport_method)(request,handshake,current,
                    namespace=policy.authority_namespace,binding=binding,method=method,**originals)
            except AuthorityChannelUnavailable:
                if attempt or method.endswith(("_claim_v3", "_claim_v1")):raise
            finally:
                await transport.close()
        raise RuntimeError("D04 original RPC remains unresolved")

    async def claim_d04_numeric_v3(self, bundle, grant, *, binding, executor_incarnation):
        return await self._d04_numeric_v3(bundle, grant, binding=binding,
            method="d04_numeric_claim_v3", executor_incarnation=executor_incarnation)

    async def d04_series_v1(self, bundle, grant, *, binding, method, **values):
        from ..authority_service.d04_series_contract_v1 import D04SeriesChunkBindingV1
        _, policy = await self._d04_installation_context_v3(bundle, grant)
        if (type(binding) is not D04SeriesChunkBindingV1 or binding.numeric.namespace != policy.namespace
                or binding.numeric.installation_id != policy.installation_id):
            raise ValueError("series actual installed client binding differs")
        return await self._execute_d04_rpc_v3(bundle, grant, binding=binding, method=method,
            transport_method="d04_series_v1", **values)

    async def d10_contact_policy_v1(self, bundle, grant, *, permit, method, **values):
        request, _, policy = await self._model_installation_context(bundle, grant)
        from dataclasses import asdict
        from .mtls_transport import MtlsAuthorityTransport
        transport = MtlsAuthorityTransport({bundle.tls_profile.profile_id: bundle.tls_profile})
        try:
            handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
            current = await transport.installation_grant_v2(request, handshake)
            expected, observed = asdict(grant), asdict(current)
            expected.pop("channel_binding_sha256")
            observed.pop("channel_binding_sha256")
            if expected != observed:
                raise RuntimeError("contact policy reconnected installation identity changed")
            # Issue/revoke are sent once. A missing ACK is resolved by the
            # protected policy operation original, never an automatic resend.
            return await transport.d10_contact_policy_v1(request, handshake, current,
                namespace=policy.authority_namespace, namespace_id=policy.namespace,
                permit=permit, method=method, **values)
        finally:
            await transport.close()

    async def read_d04_numeric_originals_v3(self, bundle, grant, *, binding):
        return await self._d04_numeric_v3(bundle, grant, binding=binding,
            method="d04_numeric_inspect_v3")

    async def record_d04_numeric_terminal_v3(self, bundle, grant, *, binding, claim, measurement):
        return await self._d04_numeric_v3(bundle, grant, binding=binding,
            method="d04_numeric_terminal_v3", claim=claim, measurement=measurement)

    async def read_d04_numeric_terminal_v3(self, bundle, grant, *, binding):
        return (await self.read_d04_numeric_originals_v3(bundle, grant, binding=binding))[1]

    async def _model_installation_context(self, bundle, grant: InstallationGrantV2):
        """Recheck installed facts and package bytes before each passive model RPC."""
        from .authority_profile import AdminInstallationBundle
        if (type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or self._transport is None
                or self._v2_request is None or self._v2_handshake is None):
            raise RuntimeError("authority model installation is unavailable")
        policy = bundle.installation_policy
        if type(policy) is not AdminInstallationPolicy:
            raise RuntimeError("authority model installation policy is invalid")
        request = self._v2_request
        handshake = self._v2_handshake
        current = await asyncio.to_thread(self._build_request)
        installed_profile = getattr(self._transport, "profile_for", None)
        if (current != request or not handshake.valid_pairing()
                or installed_profile is None
                or installed_profile(request.profile_id) != bundle.tls_profile
                or bundle.tls_profile.profile_id != request.profile_id
                or bundle.tls_profile.expected_authority_id != grant.authority_id
                or (policy.expected_authority_id, policy.installation_id,
                    policy.manifest_digest, policy.administrator_holder) !=
                   (grant.authority_id, grant.installation_id,
                    grant.manifest_digest, grant.administrator_holder)
                or grant.authority_id != handshake.installation_authority_id
                or grant.subject != handshake.installation_identity_ref
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256
                or grant.manifest_digest != request.publisher_package.manifest_sha256):
            raise RuntimeError("authority model installation binding is invalid")
        return request, handshake, policy

    async def model_fence_current_observation_v1(self,bundle,grant,*,intent):
        """Observe only this installed MODEL subject through existing paired RPCs."""
        from ..runtime_contracts import canonical_digest
        from ..runtime.restore_anchor import RestoreAnchor
        request,handshake,policy=await self._model_installation_context(bundle,grant)
        if(type(intent)is not ModelEgressIntentV1 or(intent.authority_id,intent.namespace,intent.subject)!=(
                grant.authority_id,policy.authority_namespace,grant.subject)):
            raise RuntimeError('model current observation crossed its actual installed subject/namespace')
        permit,state=await self._transport.v2_get_content_fence_operation(request,handshake,
            namespace=policy.authority_namespace,operation_id=intent.operation_id)
        anchor=await self._transport.v2_current_anchor(request,handshake,policy.authority_namespace)
        if(type(permit)is not FencePermitV2 or type(anchor)is not RestoreAnchor
                or state not in {'active','finished'}
                or(permit.authority_id,permit.namespace,permit.subject,permit.holder,permit.operation,permit.operation_id)!=(
                    grant.authority_id,policy.authority_namespace,grant.subject,grant.administrator_holder,'model_egress',intent.operation_id)
                or(permit.token,permit.fence_epoch,permit.revision)!=(intent.fence_token,intent.fence_epoch,intent.fence_revision)
                or intent.anchor_digest!=canonical_digest(permit.pinned_anchor)
                or(anchor.authority_id,anchor.namespace)!=(grant.authority_id,policy.authority_namespace)):
            raise RuntimeError('model current observation differs from its actual bound permit/anchor')
        return permit,state,anchor

    async def model_capacity_reconcile_v1(
        self, bundle, grant: InstallationGrantV2, *, expected_anchor: RestoreAnchor,
        draft: ModelEgressDraftV1 | None = None, close_prepared: bool = False,
    ) -> dict[str, object]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_capacity_reconcile_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, expected_anchor=expected_anchor,
            draft=draft, close_prepared=close_prepared)

    async def model_prepare_fenced_v1(
        self, bundle, grant: InstallationGrantV2, *, draft: ModelEgressDraftV1,
        expected_anchor: RestoreAnchor, _on_dispatch=None,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_prepare_fenced_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, draft=draft,
            expected_anchor=expected_anchor, _on_dispatch=_on_dispatch)

    async def model_admit_dispatch_once_v1(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
        expected_anchor: RestoreAnchor, model_request: ModelCallRequest,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if model_request.envelope.authority.namespace != policy.namespace:
            raise RuntimeError("authority model namespace binding is invalid")
        return await self._transport.model_admit_dispatch_once_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent,
            expected_anchor=expected_anchor, model_request=model_request)

    async def model_recover_fenced_v1(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_recover_fenced_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent)

    async def model_admit_dispatch_once_v2(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
        expected_anchor: RestoreAnchor, model_request: ModelCallRequest,
        host_incarnation: str, _on_dispatch=None,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2, ModelAdmissionV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if model_request.envelope.authority.namespace != policy.namespace:
            raise RuntimeError("authority model namespace binding is invalid")
        return await self._transport.model_admit_dispatch_once_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent,
            expected_anchor=expected_anchor, model_request=model_request,
            host_incarnation=host_incarnation, _on_dispatch=_on_dispatch)

    async def bind_observed_d13_provider_http_v1(self,bundle,grant,*,intent,admission,content):
        from .model_workflows_v7 import AdminModelWorkflowsV7
        from .model_workflows_v8 import AdminModelWorkflowsV8
        from ..authority_service.v2_model_egress_wire import to_wire as model_to_wire
        from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
        from ..authority_service.d13_provider_http_admission_v1 import DOMAIN
        from ..runtime_contracts import canonical_serialize
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64,hashlib
        if (type(bundle.model_workflows) not in {AdminModelWorkflowsV7, AdminModelWorkflowsV8}
                or type(content) is not bytes or not 0<len(content)<=65536):
            raise RuntimeError('actual installed bounded V7 SDK HTTP capture required')
        request,handshake,policy=await self._model_installation_context(bundle,grant)
        result=await self._transport._content_rpc(request,handshake,'bind_observed_d13_provider_http_v1',
            {'namespace':policy.authority_namespace,'holder':policy.administrator_holder,
                'intent':model_to_wire(intent),'admission':model_to_wire(admission),
                'http_content_base64':base64.b64encode(content).decode('ascii')},protocol=AUTHORITY_V2_PROTOCOL)
        if type(result) is not dict or set(result)!={'binding','channel_binding_sha256'} or result['channel_binding_sha256']!=handshake.channel_binding_sha256:
            raise RuntimeError('provider HTTP binding crossed its authenticated channel')
        original=result['binding']
        if type(original) is not dict or set(original)!={'original_digest','payload','signature'}:
            raise RuntimeError('closed original provider HTTP binding required')
        value=original['payload']
        required={'schema','phase','authority_namespace','installation_id','authority_id','call_id','admission_id',
            'request_digest','provider_config_digest','template_digest','http_digest','http_bytes','counter_operation_id',
            'frame_intent_digest','counter_evidence_digest','expires_at_utc','model_intent_digest','observed_at_utc'}
        if (type(value) is not dict or set(value)!=required or value['schema']!='sylanne3.d13.provider-http-binding.v1'
                or value['phase']!='observed_before_send'
                or (value['authority_namespace'],value['installation_id'],value['authority_id'])!=(policy.authority_namespace,grant.installation_id,grant.authority_id)
                or (value['call_id'],value['admission_id'],value['request_digest'],value['provider_config_digest'])!=(intent.call_id,admission.admission_id,intent.request_digest,intent.provider_config_digest)
                or value['http_digest']!=hashlib.sha256(content).hexdigest() or value['http_bytes']!=len(content)
                or value['model_intent_digest']!=canonical_digest(intent)):
            raise RuntimeError('actual provider HTTP binding differs from this original model admission')
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle.d13_wire_policy.counter_public_key_hex)).verify(
            base64.b64decode(original['signature'],validate=True),DOMAIN+canonical_serialize(value).encode('utf-8'))
        encoded=canonical_serialize({'payload':value,'signature':original['signature']}).encode('utf-8')
        if hashlib.sha256(encoded).hexdigest()!=original['original_digest']:
            raise RuntimeError('provider HTTP original digest differs')
        return original

    async def model_complete_observed_v2(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
        expected_anchor: RestoreAnchor, admission: ModelAdmissionV2,
        report: HostObservedModelCompletionV2,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2, ModelTerminalReceiptV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_complete_observed_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent,
            expected_anchor=expected_anchor, admission=admission, report=report)

    async def qualify_current_life_numeric_model_candidate_v3(
        self,bundle,grant:InstallationGrantV2,*,original_intent,original_permit,case,candidate_intent,
    ):
        request,handshake,policy=await self._model_installation_context(bundle,grant)
        return await self._transport.qualify_current_life_numeric_model_candidate_v3(
            request,handshake,grant,namespace=policy.authority_namespace,holder=policy.administrator_holder,
            original_intent=original_intent,original_permit=original_permit,case=case,candidate_intent=candidate_intent)

    async def model_terminal_fact_v2(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2, ModelAdmissionV2,
               ModelTerminalReceiptV2 | None]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_terminal_fact_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent)

    async def model_original_intent_lookup_v1(
        self, bundle, grant: InstallationGrantV2, *,
        lookup: C02OriginalIntentLookupV1,
    ) -> ModelEgressIntentV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(lookup) is not C02OriginalIntentLookupV1
                or (lookup.namespace, lookup.authority_id,
                    lookup.authority_namespace, lookup.installation_id) !=
                   (policy.namespace, grant.authority_id,
                    policy.authority_namespace, grant.installation_id)):
            raise RuntimeError("original intent lookup differs from installation")
        return await self._transport.model_original_intent_lookup_v1(
            request, handshake, grant, lookup=lookup)

    async def model_accounting_intent_lookup_v1(
        self, bundle, grant: InstallationGrantV2, *,
        lookup: C02OriginalIntentLookupV1,
    ) -> ModelEgressIntentV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(lookup) is not C02OriginalIntentLookupV1
                or (lookup.namespace, lookup.authority_id,
                    lookup.authority_namespace, lookup.installation_id) !=
                   (policy.namespace, grant.authority_id,
                    policy.authority_namespace, grant.installation_id)):
            raise RuntimeError("original intent lookup differs from installation")
        return await self._transport.model_accounting_intent_lookup_v1(
            request, handshake, grant, lookup=lookup)

    async def model_result_read_v1(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: ModelResultReadRequestV1, owner_session_token: str,
    ) -> ModelResultReadV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ModelResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id):
            raise RuntimeError("Owner result read differs from installed namespace")
        return await self._transport.model_result_read_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request, owner_session_token=owner_session_token)

    async def model_result_read_recover_finish_v1(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: ModelResultReadRequestV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ModelResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id):
            raise RuntimeError("Owner result read differs from installed namespace")
        return await self._transport.model_result_read_recover_finish_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def worker_model_result_select_attempt_v1(
        self, bundle, grant: InstallationGrantV2, *,
        first_request: WorkerModelResultReadRequestV1,
    ) -> WorkerModelResultReadRequestV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(first_request) is not WorkerModelResultReadRequestV1
                or first_request.namespace != policy.namespace
                or first_request.authority_namespace != policy.authority_namespace
                or first_request.installation_id != grant.installation_id):
            raise RuntimeError("worker read selection differs from installed namespace")
        return await self._transport.worker_model_result_select_attempt_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            first_request=first_request)

    async def worker_model_result_read_v1(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: WorkerModelResultReadRequestV1,
    ) -> WorkerModelResultReadV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not WorkerModelResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id):
            raise RuntimeError("worker result read differs from installed namespace")
        return await self._transport.worker_model_result_read_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def worker_model_result_recover_finish_v1(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: WorkerModelResultReadRequestV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not WorkerModelResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id):
            raise RuntimeError("worker result read differs from installed namespace")
        return await self._transport.worker_model_result_recover_finish_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def reply_worker_model_result_select_attempt_v1(
        self, bundle, grant: InstallationGrantV2, *,
        first_request: ReplyWorkerModelResultReadRequestV1,
    ) -> ReplyWorkerModelResultReadRequestV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(first_request) is not ReplyWorkerModelResultReadRequestV1
                or first_request.namespace != policy.namespace
                or first_request.authority_namespace != policy.authority_namespace
                or first_request.installation_id != grant.installation_id
                or first_request.authority_id != grant.authority_id):
            raise RuntimeError("reply worker read selection differs from installation")
        return await self._transport.reply_worker_model_result_select_attempt_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            first_request=first_request)

    async def reply_worker_model_result_read_v1(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: ReplyWorkerModelResultReadRequestV1,
    ) -> ReplyWorkerModelResultReadV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ReplyWorkerModelResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("reply worker result read differs from installation")
        return await self._transport.reply_worker_model_result_read_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def reply_worker_model_result_recover_finish_v1(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: ReplyWorkerModelResultReadRequestV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ReplyWorkerModelResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("reply worker result read differs from installation")
        return await self._transport.reply_worker_model_result_recover_finish_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def d04_appraisal_result_read_v3(self, bundle, grant, *, read_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if read_request.namespace != policy.namespace or read_request.authority_namespace != policy.authority_namespace:
            raise RuntimeError("D04 result namespace differs")
        return await self._transport.d04_appraisal_result_read_v3(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def d04_appraisal_result_recover_finish_v3(self, bundle, grant, *, read_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if read_request.namespace != policy.namespace or read_request.authority_namespace != policy.authority_namespace:
            raise RuntimeError("D04 result recovery namespace differs")
        return await self._transport.d04_appraisal_result_recover_finish_v3(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def d07_cognition_result_read_v1(self, bundle, grant, *, read_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if read_request.namespace != policy.namespace or read_request.authority_namespace != policy.authority_namespace:
            raise RuntimeError("D07 result namespace differs")
        return await self._transport.d07_cognition_result_read_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def contact_model_result_read_v1(self, bundle, grant, *, read_request):
        from ..authority_service.contact_model_result_contract_v1 import ContactModelResultReadRequestV1
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ContactModelResultReadRequestV1
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("contact result installed original differs")
        return await self._transport.contact_model_result_read_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def contact_model_result_recover_finish_v1(self, bundle, grant, *, read_request):
        from ..authority_service.contact_model_result_contract_v1 import ContactModelResultReadRequestV1
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ContactModelResultReadRequestV1
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("contact result recovery installed original differs")
        return await self._transport.contact_model_result_recover_finish_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def artifact_draft_model_result_read_v1(self, bundle, grant, *, read_request):
        from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadRequestV1
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ArtifactDraftModelResultReadRequestV1
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("artifact draft result installed original differs")
        return await self._transport.artifact_draft_model_result_read_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def artifact_draft_model_result_read_v2(self, bundle, grant, *, read_request):
        from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadRequestV2
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ArtifactDraftModelResultReadRequestV2
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("artifact draft result installed original differs")
        return await self._transport.artifact_draft_model_result_read_v2(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def internal_life_model_result_read_v2(self, bundle, grant, *, read_request):
        from ..authority_service.internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not InternalLifeModelResultReadRequestV2
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("Life content result installed original differs")
        return await self._transport.internal_life_model_result_read_v2(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def internal_life_model_result_recover_finish_v2(self, bundle, grant, *, read_request):
        from ..authority_service.internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not InternalLifeModelResultReadRequestV2
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("Life content result recovery installed original differs")
        return await self._transport.internal_life_model_result_recover_finish_v2(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def life_numeric_model_result_read_v1(self, bundle, grant, *, read_request):
        from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not LifeNumericModelResultReadRequestV1
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("Life numeric result installed original differs")
        return await self._transport.life_numeric_model_result_read_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def life_numeric_model_result_recover_finish_v1(self, bundle, grant, *, read_request):
        from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not LifeNumericModelResultReadRequestV1
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("Life numeric result recovery installed original differs")
        return await self._transport.life_numeric_model_result_recover_finish_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def contact_model_result_read_v2(self, bundle, grant, *, read_request):
        from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadRequestV2
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ContactModelResultReadRequestV2
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("contact result installed original differs")
        return await self._transport.contact_model_result_read_v2(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def contact_model_result_recover_finish_v2(self, bundle, grant, *, read_request):
        from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadRequestV2
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ContactModelResultReadRequestV2
                or (read_request.namespace, read_request.authority_namespace, read_request.installation_id, read_request.authority_id) !=
                   (policy.namespace, policy.authority_namespace, grant.installation_id, grant.authority_id)):
            raise RuntimeError("contact result recovery installed original differs")
        return await self._transport.contact_model_result_recover_finish_v2(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def d07_cognition_result_recover_finish_v1(self, bundle, grant, *, read_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if read_request.namespace != policy.namespace or read_request.authority_namespace != policy.authority_namespace:
            raise RuntimeError("D07 result recovery namespace differs")
        return await self._transport.d07_cognition_result_recover_finish_v1(request, handshake, grant,
            namespace=policy.authority_namespace, read_request=read_request)

    async def natural_generation_output_select_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: NaturalGenerationOutputReadRequestV2,
    ) -> NaturalGenerationOriginalOutputV2:
        request, handshake, policy = await self._model_installation_context(
            bundle, grant)
        if (type(read_request) is not NaturalGenerationOutputReadRequestV2
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("natural generation result differs from installation")
        return await self._transport.natural_generation_output_select_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def natural_generation_content_read_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: NaturalGenerationContentReadRequestV2,
    ) -> NaturalGenerationCurrentContentV2:
        request, handshake, policy = await self._model_installation_context(
            bundle, grant)
        if (type(read_request) is not NaturalGenerationContentReadRequestV2
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("natural content read differs from installation")
        return await self._transport.natural_generation_content_read_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def natural_generation_output_recover_finish_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: NaturalGenerationOutputReadRequestV2,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(
            bundle, grant)
        if (type(read_request) is not NaturalGenerationOutputReadRequestV2
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("natural generation result differs from installation")
        return await self._transport.natural_generation_output_recover_finish_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def natural_review_output_select_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: NaturalReviewOutputReadRequestV2,
    ) -> NaturalReviewOriginalOutputV2:
        request, handshake, policy = await self._model_installation_context(
            bundle, grant)
        if (type(read_request) is not NaturalReviewOutputReadRequestV2
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("natural review result differs from installation")
        return await self._transport.natural_review_output_select_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def natural_review_output_recover_finish_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: NaturalReviewOutputReadRequestV2,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(
            bundle, grant)
        if (type(read_request) is not NaturalReviewOutputReadRequestV2
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("natural review result differs from installation")
        return await self._transport.natural_review_output_recover_finish_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def natural_paid_review_current_read_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: NaturalPaidReviewCurrentReadRequestV2,
    ) -> NaturalPaidReviewCurrentReadV2:
        request, handshake, policy = await self._model_installation_context(
            bundle, grant)
        if (type(read_request) is not NaturalPaidReviewCurrentReadRequestV2
                or read_request.namespace != policy.namespace
                or read_request.generation_content_request.authority_namespace
                   != policy.authority_namespace
                or read_request.generation_content_request.installation_id
                   != grant.installation_id
                or read_request.generation_content_request.authority_id
                   != grant.authority_id):
            raise RuntimeError("natural paid review differs from installation")
        return await self._transport.natural_paid_review_current_read_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def context_reply_result_read_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: ContextReplyResultReadRequestV1,
    ) -> ContextReplyPaidResultReadV2:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ContextReplyResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("context reply result read differs from installation")
        return await self._transport.context_reply_result_read_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def context_reply_result_recover_finish_v2(
        self, bundle, grant: InstallationGrantV2, *,
        read_request: ContextReplyResultReadRequestV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(read_request) is not ContextReplyResultReadRequestV1
                or read_request.namespace != policy.namespace
                or read_request.authority_namespace != policy.authority_namespace
                or read_request.installation_id != grant.installation_id
                or read_request.authority_id != grant.authority_id):
            raise RuntimeError("context reply result read differs from installation")
        return await self._transport.context_reply_result_recover_finish_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            read_request=read_request)

    async def self_identity_current_v1(
        self, bundle, grant: InstallationGrantV2, *,
        current_request: SelfIdentityCurrentRequestV1,
    ) -> AuthorityCurrentSelfIdentityV1 | None:
        """Read only the Authority-current mapping under the caller's live fence."""
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(current_request) is not SelfIdentityCurrentRequestV1
                or (current_request.authority_id,
                    current_request.authority_namespace, current_request.namespace,
                    current_request.installation_id, current_request.manifest_digest,
                    current_request.permit.subject, current_request.permit.holder) !=
                   (grant.authority_id, policy.authority_namespace,
                    policy.namespace, grant.installation_id,
                    grant.manifest_digest, grant.subject,
                    grant.administrator_holder)):
            raise RuntimeError("self identity read differs from installed namespace")
        # A passive current read may follow minutes of installed CPU work. The
        # original business channel can have closed during that interval; use a
        # new authenticated channel without replacing unrelated live ports.
        from dataclasses import asdict
        from .mtls_transport import MtlsAuthorityTransport
        transport = MtlsAuthorityTransport({bundle.tls_profile.profile_id: bundle.tls_profile})
        try:
            current_handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
            current_grant = await transport.installation_grant_v2(request, current_handshake)
            original_identity, current_identity = asdict(grant), asdict(current_grant)
            original_identity.pop("channel_binding_sha256")
            current_identity.pop("channel_binding_sha256")
            if original_identity != current_identity:
                raise RuntimeError("self identity reconnected installation identity changed")
            return await transport.self_identity_current_v1(
                request, current_handshake, current_grant, namespace=policy.authority_namespace,
                current_request=current_request)
        finally:
            await transport.close()

    async def worker_result_read_fact_v1(
        self, bundle, grant: InstallationGrantV2, *,
        fact_request: WorkerResultReadFactRequestV1,
    ) -> WorkerResultReadFactV1:
        """Read the content-free original handoff fact under a live C02 fence."""
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(fact_request) is not WorkerResultReadFactRequestV1
                or (fact_request.read_request.authority_id,
                    fact_request.read_request.authority_namespace,
                    fact_request.read_request.namespace,
                    fact_request.read_request.installation_id,
                    fact_request.write_permit.subject,
                    fact_request.write_permit.holder,
                    fact_request.write_permit.operation_id) !=
                   (grant.authority_id, policy.authority_namespace,
                    policy.namespace, grant.installation_id,
                    grant.subject, grant.administrator_holder,
                    fact_request.read_request.consumer_operation_id)):
            raise RuntimeError("worker result fact differs from installed C02 fence")
        return await self._transport.worker_result_read_fact_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            fact_request=fact_request)

    async def worker_result_read_fact_v2(
        self, bundle, grant: InstallationGrantV2, *,
        fact_request: WorkerResultReadFactRequestV2,
    ) -> WorkerResultReadFactV2:
        """Read the bundled C02 handoff fact under its exact graph write fence."""
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if (type(fact_request) is not WorkerResultReadFactRequestV2
                or (fact_request.read_request.authority_id,
                    fact_request.read_request.authority_namespace,
                    fact_request.read_request.namespace,
                    fact_request.read_request.installation_id,
                    fact_request.write_permit.subject,
                    fact_request.write_permit.holder,
                    fact_request.write_permit.operation_id) !=
                   (grant.authority_id, policy.authority_namespace,
                    policy.namespace, grant.installation_id,
                    grant.subject, grant.administrator_holder,
                    domain_bundle_write_attempt_id_v1(
                        policy.namespace,
                        fact_request.read_request.consumer_operation_id,
                        fact_request.bundle_digest))):
            raise RuntimeError("worker result fact differs from installed C02 fence")
        return await self._transport.worker_result_read_fact_v2(
            request, handshake, grant, namespace=policy.authority_namespace,
            fact_request=fact_request)

    async def internal_accounting_v1(self,bundle,grant,*,accounting_request,action,accounting_grant=None):
        return await self._execute_c04_original_rpc_v3(bundle,grant,method="internal_accounting_v1",
            accounting_request=accounting_request,action=action,accounting_grant=accounting_grant)

    async def accounting_begin_v1(
        self, bundle, grant: InstallationGrantV2, *,
        accounting_request: AccountingMaintenanceRequestV1,
    ) -> AccountingMaintenanceGrantV1:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.accounting_begin_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder,
            accounting_request=accounting_request)

    async def accounting_validate_v1(
        self, bundle, grant: InstallationGrantV2, *,
        accounting_request: AccountingMaintenanceRequestV1,
        accounting_grant: AccountingMaintenanceGrantV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.accounting_validate_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, accounting_request=accounting_request,
            accounting_grant=accounting_grant)

    async def accounting_finish_v1(
        self, bundle, grant: InstallationGrantV2, *,
        accounting_request: AccountingMaintenanceRequestV1,
        accounting_grant: AccountingMaintenanceGrantV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.accounting_finish_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, accounting_request=accounting_request,
            accounting_grant=accounting_grant)

    async def accounting_recover_finish_v1(
        self, bundle, grant: InstallationGrantV2, *,
        accounting_request: AccountingMaintenanceRequestV1,
    ) -> bool:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.accounting_recover_finish_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, accounting_request=accounting_request)

    async def capability_grant(self) -> AuthorityCapabilityGrant | None:
        """Return a complete runtime grant; enrollment-only facts remain blocked."""
        grant = await self.enrollment_grant()
        return (
            grant
            if isinstance(grant, AuthorityCapabilityGrant)
            and self._handshake is not None
            and grant.valid_for(self._handshake)
            else None
        )

    async def enrollment_grant(
        self,
    ) -> AuthorityEnrollmentGrant | AuthorityCapabilityGrant | None:
        """Fetch a paired-installation fact without treating it as runtime-ready."""
        if self._transport is None:
            return None
        if self._request is None or self._handshake is None:
            status = await self.status()
            if status.state != "paired":
                return None
        assert self._request is not None and self._handshake is not None
        try:
            grant = await self._transport.capability_grant(
                self._request, self._handshake
            )
        except Exception:
            return None
        if isinstance(grant, AuthorityEnrollmentGrant):
            return grant if grant.valid_for(self._handshake) else None
        if isinstance(grant, AuthorityCapabilityGrant):
            return grant if grant.valid_for(self._handshake) else None
        return None


    async def model_no_dispatch_witness_v1(self, bundle, grant, *, closure_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_no_dispatch_witness_v1(request, handshake, grant,
            namespace=policy.authority_namespace, holder=policy.administrator_holder, closure_request=closure_request)

    async def model_no_dispatch_accounting_begin_v1(self, bundle, grant, *, accounting_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_no_dispatch_accounting_begin_v1(request, handshake, grant,
            namespace=policy.authority_namespace, holder=policy.administrator_holder, accounting_request=accounting_request)

    async def model_no_dispatch_accounting_validate_v1(self, bundle, grant, *, accounting_request, accounting_grant):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_no_dispatch_accounting_validate_v1(request, handshake, grant,
            namespace=policy.authority_namespace, holder=policy.administrator_holder,
            accounting_request=accounting_request, accounting_grant=accounting_grant)

    async def model_no_dispatch_accounting_finish_v1(self, bundle, grant, *, accounting_request, accounting_grant):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_no_dispatch_accounting_finish_v1(request, handshake, grant,
            namespace=policy.authority_namespace, holder=policy.administrator_holder,
            accounting_request=accounting_request, accounting_grant=accounting_grant)

    async def model_no_dispatch_accounting_recover_finish_v1(self, bundle, grant, *, accounting_request):
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_no_dispatch_accounting_recover_finish_v1(request, handshake, grant,
            namespace=policy.authority_namespace, holder=policy.administrator_holder, accounting_request=accounting_request)



__all__ = (
    "AUTHORITY_PROTOCOL",
    "AuthorityClient",
    "AuthorityClientStatus",
    "AuthorityEnrollmentGrant",
    "AuthorityCapabilityGrant",
    "AuthorityHandshake",
    "AuthorityProvisioningRequest",
    "AuthoritySelection",
    "AuthorityTransport",
    "PublisherPackageIdentity",
    "REQUIRED_AUTHORITY_CAPABILITIES",
)
