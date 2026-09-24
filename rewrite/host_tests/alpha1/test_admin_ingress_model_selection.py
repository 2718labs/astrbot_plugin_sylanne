"""Admin model selection is parsed exactly and checked against the installed host."""

import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sylanne3.host.authority_profile import (
    AdminIngressModelPolicy, AdminIngressEncodingPolicy, AdminInstallationBundle,
    installed_model_config_ref, _ingress_model_from_payload,
    _policy_from_payload, _read_profile_json,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest

from test_authority_profile import _schema2_payload


def _selection(config=None):
    digest = canonical_digest(config if config is not None else {"model": "model-1"})
    return {
        "provider_id": "provider-1", "model_id": "model-1",
        "provider_config_ref": installed_model_config_ref(
            "provider-1", "model-1", digest),
        "provider_config_digest": digest,
        "timeout_seconds": 20.0, "max_output_tokens": 128,
        "required_capabilities": ["structured"], "privacy_tier": "private",
    }


def test_admin_profile_keeps_model_selector_outside_installation_policy(tmp_path):
    payload = _schema2_payload()
    before = _policy_from_payload(payload).digest_payload()
    payload["ingress_model"] = _selection()
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps(payload), encoding="utf-8")
    loaded = _read_profile_json(profile)
    assert _policy_from_payload(loaded).digest_payload() == before
    assert _ingress_model_from_payload(loaded) == AdminIngressModelPolicy(
        **(_selection() | {"required_capabilities": ("structured",)}))


@pytest.mark.parametrize("change", [
    {"provider_id": ""}, {"model_id": " "},
    {"provider_config_digest": "bad"}, {"timeout_seconds": 0},
    {"provider_config_ref": "admin:unverified-ref"},
    {"timeout_seconds": 10 ** 1000}, {"max_output_tokens": 0},
    {"max_output_tokens": True}, {"required_capabilities": []},
    {"required_capabilities": ["structured", "structured"]},
    {"required_capabilities": "structured"}, {"extra": "field"},
])
def test_invalid_admin_model_selection_fails_profile_parse(change):
    payload = _schema2_payload()
    payload["ingress_model"] = _selection() | change
    with pytest.raises((TypeError, ValueError)):
        _policy_from_payload(payload)


def test_model_output_budget_requires_same_dimension_in_quote_lease_and_grant():
    payload = _schema2_payload()
    payload["ingress_model"] = _selection() | {"max_output_tokens": 64}
    payload["ingress_encoding"] = {
        "deadline_after_seconds": 5, "quote_ceiling": {"output_tokens": 64},
        "snapshot_ref": "snapshot", "resource_ref": "resource",
        "character_interval_ref": "interval",
    }
    for missing in ("quote", "lease", "grant"):
        changed = json.loads(json.dumps(payload))
        if missing == "quote":
            changed["ingress_encoding"]["quote_ceiling"]["output_tokens"] = 63
        elif missing == "lease":
            changed["installation_policy"]["root_lease"]["limits"] = {"tokens": 1000}
        else:
            changed["installation_policy"]["root_grant"]["max_ceiling"] = {"tokens": 100}
        with pytest.raises(ValueError, match="output_tokens"):
            _policy_from_payload(changed)


def test_explicit_admin_scope_is_required_and_validated():
    payload = _schema2_payload()
    payload["ingress_model"] = _selection() | {
        "allowed_purposes": ["proposal"],
        "allowed_audiences": ["owner"],
        "allowed_privacy_tiers": ["private"],
    }
    selection = _ingress_model_from_payload(payload)
    assert selection.allowed_purposes == ("proposal",)
    assert selection.allowed_audiences == ("owner",)
    assert selection.allowed_privacy_tiers == ("private",)
    for field in ("allowed_purposes", "allowed_audiences", "allowed_privacy_tiers"):
        changed = json.loads(json.dumps(payload))
        changed["ingress_model"][field] = []
        with pytest.raises(ValueError):
            _policy_from_payload(changed)


@pytest.mark.asyncio
async def test_admin_selection_checks_exact_current_provider_and_config():
    pytest.importorskip("astrbot")
    from astrbot.api.star import Context
    from astrbot.core.provider.entities import ProviderMeta, ProviderType
    from astrbot.core.provider.provider import Provider
    from sylanne3.host.installed_model_capability import InstalledModelCapabilityPort

    class InstalledProvider(Provider):
        def __init__(self):
            self.provider_config = {"model": "model-1"}
            self.client = SimpleNamespace()
            self.model_name = "model-1"

        def meta(self):
            return ProviderMeta("provider-1", self.model_name, "openai_chat_completion",
                                ProviderType.CHAT_COMPLETION)

        def get_current_key(self):
            raise AssertionError("verification must not read a credential")

        def set_key(self, key):
            raise AssertionError("verification must not alter a credential")

        async def get_models(self):
            raise AssertionError("verification must not call a provider")

        async def text_chat(self, *args, **kwargs):
            raise AssertionError("verification must not call a model")

    provider = InstalledProvider()
    manager = SimpleNamespace(
        provider_insts=[provider], inst_map={"provider-1": provider},
    )
    context = Context(asyncio.Queue(), {}, None, manager, None, None,
                      None, None, None, None, None)
    namespace = NamespaceId("bot-a", "persona-a")
    port = InstalledModelCapabilityPort(
        context=context, host_loop=asyncio.get_running_loop(),
        installed_namespace=namespace,
    )
    selection = AdminIngressModelPolicy(**(
        _selection(provider.provider_config)
        | {"required_capabilities": ("structured",)}))
    with (patch("sylanne3.host.installed_model_capability.ProviderOpenAIOfficial",
                InstalledProvider),
          patch("sylanne3.host.installed_model_capability.AsyncOpenAI",
                SimpleNamespace)):
        assert await asyncio.to_thread(port.verify_admin_config,
                                       namespace, selection)
        assert not await asyncio.to_thread(port.verify_admin_selection,
                                           namespace, selection)
        payload = _schema2_payload()
        payload["installation_policy"]["root_lease"]["limits"]["output_tokens"] = 256
        payload["installation_policy"]["root_grant"]["max_ceiling"]["output_tokens"] = 128
        policy = _policy_from_payload(payload)
        encoding = AdminIngressEncodingPolicy(
            5, {"output_tokens": 128}, "snapshot", "resource", "interval")
        authorized = replace(
            selection, required_capabilities=("text",),
            allowed_purposes=("proposal",), allowed_audiences=("owner",),
            allowed_privacy_tiers=("private",),
        )
        bundle = AdminInstallationBundle(
            SimpleNamespace(), policy, b"k" * 32, b"d" * 32,
            ingress_encoding=encoding, ingress_model=authorized,
        )
        eligible = InstalledModelCapabilityPort(
            context=context, host_loop=asyncio.get_running_loop(),
            installed_namespace=namespace, installation_bundle=bundle,
        )
        assert await asyncio.to_thread(eligible.verify_admin_selection,
                                       namespace, authorized)
        assert not await asyncio.to_thread(
            eligible.verify_admin_selection, namespace,
            replace(authorized, required_capabilities=("structured",)))
        assert not await asyncio.to_thread(
            eligible.verify_admin_selection, namespace,
            replace(authorized, privacy_tier="secret"))
        provider.provider_config["temperature"] = 0.5
        assert not await asyncio.to_thread(port.verify_admin_config,
                                           namespace, selection)
        assert not await asyncio.to_thread(eligible.verify_admin_selection,
                                           namespace, authorized)
        provider.provider_config.pop("temperature")
        provider.model_name = "model-2"
        assert not await asyncio.to_thread(port.verify_admin_config,
                                           namespace, selection)
        provider.model_name = "model-1"
        manager.inst_map.clear()
        assert not await asyncio.to_thread(port.verify_admin_config,
                                           namespace, selection)
    assert not port.verify_admin_config(namespace, selection)
