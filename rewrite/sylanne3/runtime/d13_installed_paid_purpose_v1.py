"""Exact installed D13 context purpose, without issuing any egress authority.

These checks select the Host descriptor's purpose. Actual current rights,
signed grants, original jobs/quotes/reservations and one-shot admission remain
the responsibility of the existing pinned Graph and authenticated Core ports.
"""
from __future__ import annotations


def installed_d13_paid_context_model_v1(bundle, model) -> bool:
    from ..host.authority_profile import AdminInstallationBundle, AdminModelWorkflowV2
    from ..installation_policy import AdminInstallationPolicy
    from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
    from .d13_technical_policy import AdminD13PaidPrecompressionPolicyV1

    if (type(bundle) is not AdminInstallationBundle
            or type(bundle.installation_policy) is not AdminInstallationPolicy
            or type(model) is not AdminModelWorkflowV2
            or bundle.model_workflows is None
            or model is not bundle.model_workflows.reply
            or type(bundle.d13_paid_precompression) is not AdminD13PaidPrecompressionPolicyV1):
        return False
    installation, d13 = bundle.installation_policy, bundle.d13_paid_precompression
    grant, lease = installation.root_grant, installation.root_lease
    if ((d13.namespace, d13.installation_id, d13.grant_id,
         d13.grant_version, d13.lease_id) != (
            installation.namespace, installation.installation_id,
            grant.grant_id, grant.version, lease.lease_id)
            or grant.lease_id != lease.lease_id
            or (grant.bot_id, grant.persona_id) != installation.namespace.as_tuple
            or (lease.bot_id, lease.persona_id) != installation.namespace.as_tuple
            or lease.state != "active"
            or d13.work_kind not in grant.allowed_work_kinds
            or model.work_kind not in grant.allowed_work_kinds
            or d13.selected_main != D13PrecompressionInstallationV1(
                installation.installation_id, model.provider_id, model.model_id,
                model.provider_config_digest, model.max_output_tokens)):
        return False
    return all(amount <= lease.limits.get(dimension, 0)
               and amount <= grant.max_ceiling.get(dimension, 0)
               for ceiling in (d13.quote_ceiling, model.quote_ceiling)
               for dimension, amount in ceiling.items())


def installed_d13_paid_context_request_v1(bundle, model, request) -> bool:
    from ..model_broker.broker import ModelCallRequest

    if (not installed_d13_paid_context_model_v1(bundle, model)
            or type(request) is not ModelCallRequest):
        return False
    authority, installation = request.envelope.authority, bundle.installation_policy
    # Expiration/revocation require the paired current clock and Authority
    # state. This static check cannot substitute for those downstream reads.
    return (request.identity.phase == "d13.precompress"
            and authority.purpose == "context"
            and authority.issuer_domain == "d13"
            and type(authority.worker_fence) is int and authority.worker_fence > 0
            and authority.namespace == installation.namespace
            and request.envelope.parent_budget_lease_ref == bundle.d13_paid_precompression.lease_id
            and 0 < request.envelope.deadline_utc <= installation.root_grant.valid_until_utc
            and request.provider_id == model.provider_id
            and request.model_id == model.model_id
            and request.max_output_tokens == model.max_output_tokens)


__all__ = ("installed_d13_paid_context_model_v1", "installed_d13_paid_context_request_v1")
