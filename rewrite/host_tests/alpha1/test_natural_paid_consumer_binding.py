"""Installed paid readiness follows the exact graph and Authority adapters."""

from __future__ import annotations

from dataclasses import replace
from threading import RLock
from types import SimpleNamespace

from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.host.authority_client import (
    AuthorityClient, AuthorityHandshake, AuthoritySelection,
)
from sylanne3.host.authority_profile import (
    AdminInstallationBundle, AdminModelWorkflowV2, AdminModelWorkflowsV2,
    NATURAL_GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION,
)
from sylanne3.host.natural_generation_content_port import (
    InstalledNaturalGenerationContentPortV2,
)
from sylanne3.host.natural_generation_output_port import (
    InstalledNaturalGenerationOutputPortV2,
)
from sylanne3.host.natural_paid_review_port import InstalledNaturalPaidReviewPortV2
from sylanne3.host.natural_review_output_port import InstalledNaturalReviewOutputPortV2
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.runtime_contracts import InstallationGrantV2, NamespaceId


def _set(instance, **values):
    for name, value in values.items():
        object.__setattr__(instance, name, value)
    return instance


def test_natural_paid_readiness_rechecks_bound_graph_and_workflow_identity():
    namespace = NamespaceId("bot", "persona")
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher", "v2", "b" * 64)
    port_grant = replace(grant, channel_binding_sha256="f" * 64)
    client_grant = replace(grant, channel_binding_sha256="e" * 64)
    handshake = AuthorityHandshake(
        "paired", "authority", "installation", "b" * 64, True)
    port_handshake = replace(handshake, channel_binding_sha256="f" * 64)
    client_handshake = replace(handshake, channel_binding_sha256="e" * 64)
    request = SimpleNamespace(profile_id="profile")
    policy = SimpleNamespace(
        namespace=namespace, authority_namespace="authority:namespace",
        installation_id="installation", manifest_digest="a" * 64)
    generation = _set(AdminModelWorkflowV2.__new__(AdminModelWorkflowV2),
                      work_kind="natural_generation", purpose="proposal",
                      template_version=NATURAL_GENERATION_TEMPLATE_VERSION,
                      provider_id="provider-a", model_id="model-a",
                      provider_config_digest="c" * 64)
    review = _set(AdminModelWorkflowV2.__new__(AdminModelWorkflowV2),
                  work_kind="natural_review", purpose="proposal",
                  template_version=REVIEW_TEMPLATE_VERSION,
                  provider_id="provider-b", model_id="model-b",
                  provider_config_digest="d" * 64)
    workflows = _set(AdminModelWorkflowsV2.__new__(AdminModelWorkflowsV2),
                     natural_generation=generation, natural_review=review)
    bundle = _set(AdminInstallationBundle.__new__(AdminInstallationBundle),
                  installation_policy=policy, model_workflows=workflows,
                  tls_profile=SimpleNamespace(
                      profile_id="profile", expected_authority_id="authority"))
    client = AuthorityClient.__new__(AuthorityClient)
    client._selection = AuthoritySelection("profile")
    client._v2_request = request
    client._v2_handshake = client_handshake
    owner_loop = SimpleNamespace(is_running=lambda: True)
    graph = GraphCoordinator.__new__(GraphCoordinator)
    port = V2FencePort.__new__(V2FencePort)
    port._lock = RLock()
    port._closed = False
    port._grant = port_grant
    port._installation_grant = grant
    port._handshake = port_handshake
    port._request = request
    port._mapped_namespaces = {namespace: "authority:namespace"}
    port._natural_paid_consumer_binding = None
    graph._GraphCoordinator__content_fence_v2 = port

    specs = (
        ("_GraphCoordinator__natural_generation_output_port",
         InstalledNaturalGenerationOutputPortV2,
         "read_original_natural_generation_output_v2"),
        ("_GraphCoordinator__natural_generation_content_port",
         InstalledNaturalGenerationContentPortV2,
         "read_current_natural_generation_content_v2"),
        ("_GraphCoordinator__natural_review_output_port",
         InstalledNaturalReviewOutputPortV2,
         "read_original_natural_review_output_v2"),
        ("_GraphCoordinator__natural_paid_review_current_port",
         InstalledNaturalPaidReviewPortV2,
         "read_current_natural_paid_review_v2"),
    )
    for attribute, kind, method in specs:
        adapter = kind.__new__(kind)
        adapter._client, adapter._bundle, adapter._grant = (
            client, bundle, client_grant)
        adapter._loop = owner_loop
        setattr(graph, attribute, getattr(adapter, method))

    assert port.natural_paid_consumer_ready_v2(
        namespace=namespace,
        template_version=NATURAL_GENERATION_TEMPLATE_VERSION) is False
    assert port.bind_natural_paid_consumers_v2(graph, bundle, grant) is True
    assert port.natural_paid_consumer_ready_v2(
        namespace=namespace,
        template_version=NATURAL_GENERATION_TEMPLATE_VERSION,
        installation_id="installation", provider_id="provider-a",
        model_id="model-a", provider_config_digest="c" * 64) is True
    assert port.natural_review_paid_consumer_ready_v2(
        namespace=namespace, template_version=REVIEW_TEMPLATE_VERSION,
        installation_id="installation", provider_id="provider-b",
        model_id="model-b", provider_config_digest="d" * 64) is True
    assert port.natural_review_paid_consumer_ready_v2(
        namespace=namespace, template_version=REVIEW_TEMPLATE_VERSION,
        installation_id="installation", provider_id="provider-a",
        model_id="model-b", provider_config_digest="d" * 64) is False
    graph._GraphCoordinator__natural_generation_output_port.__self__._grant = grant
    assert port.natural_paid_consumer_ready_v2(
        namespace=namespace,
        template_version=NATURAL_GENERATION_TEMPLATE_VERSION) is False
    graph._GraphCoordinator__natural_generation_output_port.__self__._grant = (
        client_grant)
    port._mapped_namespaces.clear()
    assert port.natural_paid_consumer_ready_v2(
        namespace=namespace,
        template_version=NATURAL_GENERATION_TEMPLATE_VERSION) is False
    port._mapped_namespaces[namespace] = "authority:namespace"
    graph._GraphCoordinator__natural_review_output_port = None
    assert port.natural_paid_consumer_ready_v2(
        namespace=namespace,
        template_version=NATURAL_GENERATION_TEMPLATE_VERSION) is False
