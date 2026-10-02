"""Read-only installed D13 raw history bridge for a private inbound turn.

The graph worker issues the current D11 window. The selected AstrBot main
conversation model supplies the live configuration identity. This produces
only low-trust model input material; no cache write, model call or budget use.
"""

from __future__ import annotations

from .model_workflows_v3 import AdminModelWorkflowsV3
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..domains.d13.provider import ShortContextProjectionQueryV1
from ..model_broker.d13_context_frame import (
    D13ContextInputFrameV1, build_d13_context_input_frame_v1,
)
from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
from ..runtime.first_ingress_v2 import ingress_ids, scene_ref_for_conversation
from ..runtime_contracts import (
    AuthorityContext, ConversationWindowProjectionV1, ShortContextRequestV1,
    ShortContextSliceV1, canonical_digest,
)
from .authority_profile import (
    AdminD13PrecompressionPolicyV1, AdminInstallationBundle,
    AdminModelWorkflowsV2,
)
from .ingress import HostIngressEnvelope

if TYPE_CHECKING:
    from .astrbot_model_call import AstrBotModelProvider


@dataclass(frozen=True, slots=True)
class InstalledD13ContextFrameReadV1:
    query: ShortContextProjectionQueryV1
    frame: D13ContextInputFrameV1
    context_slice: ShortContextSliceV1


async def read_installed_d13_raw_context_frame_v1(
    runtime, model_provider: AstrBotModelProvider, *,
    envelope: HostIngressEnvelope, ingress_operation_id: str,
) -> InstalledD13ContextFrameReadV1 | None:
    """Read one current raw D13 page under D11 authority and live UMO model.

    A later model egress must re-read D11 access and count exact provider
    input tokens. The candidate here cannot authorize a paid call or reply.
    """
    from ..runtime_context import RuntimeContext
    from .astrbot_model_call import AstrBotModelProvider

    if (type(runtime) is not RuntimeContext
            or type(model_provider) is not AstrBotModelProvider
            or type(envelope) is not HostIngressEnvelope
            or envelope.visibility != "private"
            or type(ingress_operation_id) is not str
            or ingress_ids(envelope.lineage.source_ref)[2] != ingress_operation_id):
        return None
    policy = runtime._v2_policy
    bundle = runtime._v2_model_bundle
    grant = runtime._v2_installation_grant
    port = runtime._v2_port
    worker = runtime._worker
    bootstrap = runtime._v2_bootstrap
    if (policy is None or type(bundle) is not AdminInstallationBundle
            or bundle.installation_policy != policy
            or type(bundle.d13_precompression)
               is not AdminD13PrecompressionPolicyV1
            or type(bundle.model_workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3)
            or grant is None or port is None or worker is None
            or bootstrap is None or not runtime._v2_namespace_provisioned
            or policy.namespace != envelope.namespace
            or policy.namespace != runtime._v2_namespace):
        return None
    installed = runtime.installed_d13_main_model_v1()
    try:
        selected = await model_provider.selected_d13_main_installation_v1()
    except Exception:
        return None
    if (type(installed) is not D13PrecompressionInstallationV1
            or selected != installed):
        return None
    scene_ref = scene_ref_for_conversation(
        policy.namespace, envelope.platform_ref, envelope.conversation_ref)

    def read(graph):
        anchor = port.current_anchor(
            namespace=policy.namespace,
            authority_namespace=policy.authority_namespace,
        )
        lease, capability = graph.grant(
            bootstrap, actor=grant.subject, issuer_domain="d11",
            namespace=policy.namespace, domains=("d11",),
            activation_generation=anchor.activation_generation,
            operation_id=ingress_operation_id,
        )
        try:
            authority = AuthorityContext(
                grant.subject, "d11", capability, policy.namespace,
                ("persona",), "context", (envelope.conversation_ref,),
                policy.root_grant.policy_ref, anchor.activation_generation,
            )
            return graph.read_current_d13_conversation_window_v1(
                authority, lease, scene_ref=scene_ref,
                max_slots=bundle.d13_precompression.max_slots,
            )
        finally:
            graph.release_authority_lease(bootstrap, lease)

    try:
        window = await worker.call(read)
    except Exception:
        return None
    if (type(window) is not ConversationWindowProjectionV1
            or window.namespace != policy.namespace
            or window.conversation_ref != envelope.conversation_ref):
        return None
    main = bundle.model_workflows.reply
    request = ShortContextRequestV1(
        "d09", "reply", window.conversation_ref, window.scene_ref,
        window.audience_ref,
        "d13:frame:" + canonical_digest({
            "ingress_operation_id": ingress_operation_id,
            "window_read_set": window.read_set,
            "order_watermark": window.order_watermark,
        }),
        None, bundle.d13_precompression.history_token_budget,
        selected.provider_id, selected.model_id, main.template_version,
        "no-tools.v1", policy.root_lease.lease_id, True,
    )
    query = ShortContextProjectionQueryV1(window, request)
    try:
        frame, context_slice = build_d13_context_input_frame_v1(
            query, current_window=window, selected_main_model=selected,
        )
    except (TypeError, ValueError):
        return None
    return InstalledD13ContextFrameReadV1(query, frame, context_slice)


__all__ = [
    "InstalledD13ContextFrameReadV1",
    "read_installed_d13_raw_context_frame_v1",
]
