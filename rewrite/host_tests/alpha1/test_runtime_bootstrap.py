from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import importlib
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest.mock import AsyncMock, patch

from astrbot.api.event import AstrMessageEvent
from astrbot.api.platform import AstrBotMessage, MessageMember, MessageType, PlatformMetadata
from astrbot.api.message_components import Image
from astrbot.api.star import Context, Star, StarTools
from astrbot.core.star.filter.event_message_type import EventMessageTypeFilter
from astrbot.core.star.star_handler import star_handlers_registry

from sylanne3.domain_registry import REQUIRED_DOMAINS, discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import (
    GraphCoordinator, IngressClockSample, IngressIssuancePolicy,
)
from sylanne3.graph_types import OWNER_GRANT_TYPE
from sylanne3.host import (
    AuthorizedIngressCommit,
    CanonicalIngressObservation,
    IngressAuthoritySession,
    IngressReceipt,
    build_astrbot_ingress,
    build_d06_ingress_handler,
    source_admission_from_host,
)
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.d06_ingress import ingress_source_identity
from sylanne3.host.ingress_assembler import ingress_content_fingerprint
from sylanne3.runtime.ingress_contracts import CommittedIngressReplay
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    CommitReceipt,
    DependencySet,
    DomainBundle,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    RUNTIME_SCHEMA,
    VersionGuard,
    canonical_digest,
)
from sylanne3.runtime_context import RuntimeContext, RuntimeDependencies, RuntimeHealth


ROOT = Path(__file__).resolve().parents[3]
MODULE = "data.plugins.sylanne3_alpha1.main"


def registry_with_test_affect_scheme():
    return discover_domain_registry(active_affect_scheme=AffectScheme(
        "d04.affect.scheme.v1", "test-scheme", "test-operator",
        "test-parameters", "test-coupling",
        (AffectAxis("care", "normalized", "care for another"),), (),
    ))


def controlled_ingress_policy(namespace: NamespaceId, policy_ref: str) -> IngressIssuancePolicy:
    """Test fixture only; these values are not installation authority grants."""
    return IngressIssuancePolicy(
        parent_budget_lease_ref="fixture-budget-lease",
        ceiling={"tokens": 1}, grant_ceiling={"tokens": 1},
        deadline_utc=time.time() + 60,
        grant_valid_until_utc=time.time() + 120,
        monotonic_deadline=time.monotonic() + 60,
        snapshot_ref="fixture-snapshot", resource_ref="fixture-resource",
        character_interval_ref="fixture-interval",
    )


def controlled_ingress_clock() -> IngressClockSample:
    """Controlled test injection; local process time is not a production trust root."""
    return IngressClockSample(
        time.time(), time.monotonic(), "fixture-clock-epoch", True
    )


def load_plugin_module():
    for name, path in {
        "data": ROOT,
        "data.plugins": ROOT,
        "data.plugins.sylanne3_alpha1": ROOT,
    }.items():
        package = sys.modules.get(name)
        if package is None:
            package = types.ModuleType(name)
            package.__package__ = name
            sys.modules[name] = package
        package.__path__ = [str(path)]
    sys.modules.pop(MODULE, None)
    return importlib.import_module(MODULE)


class Event(AstrMessageEvent):
    def __init__(self, *, timestamp: float = 10, text: str = "hello") -> None:
        message = AstrBotMessage()
        message.type = MessageType.FRIEND_MESSAGE
        message.self_id = "bot-1"
        message.session_id = "session-1"
        message.message_id = "message-1"
        message.sender = MessageMember("sender-1", "Sender")
        message.message = []
        message.message_str = text
        message.raw_message = {}
        message.timestamp = timestamp
        super().__init__(
            text,
            message,
            PlatformMetadata("controlled", "controlled", "adapter-1"),
            "session-1",
        )
        self.sent = []

    async def send(self, message):
        self.sent.append(message)


class _ConversationManager:
    async def get_curr_conversation_id(self, umo):
        return "conversation-1"

    async def get_conversation(self, umo, conversation_id, create_if_not_exists=False):
        if create_if_not_exists:
            raise AssertionError("ingress must not create a conversation")
        return types.SimpleNamespace(persona_id="persona-1")


class _PersonaManager:
    async def resolve_selected_persona(self, **kwargs):
        return "persona-1", {}, None, False


class _IngressContext:
    conversation_manager = _ConversationManager()
    persona_manager = _PersonaManager()

    @staticmethod
    def get_config(umo):
        return {}


class RuntimeBootstrapTests(unittest.IsolatedAsyncioTestCase):
    def test_default_catalogue_registers_types_but_requires_an_active_d04_scheme(self) -> None:
        registry = discover_domain_registry()
        self.assertEqual(set(registry.required_domains), set(REQUIRED_DOMAINS))
        self.assertEqual(set(registry.registrations), set(REQUIRED_DOMAINS))
        self.assertFalse(registry.complete)
        self.assertEqual(
            dict(registry.unavailable),
            {"d04": "active D04 scheme is required for a complete registry"},
        )
        self.assertIn("d12", registry.registrations)
        self.assertTrue(registry.type_registry.specs)
        self.assertTrue(all(spec.writer_domain for spec in registry.type_registry.specs))

    def test_owner_grant_has_one_reserved_d11_catalogue_spec(self) -> None:
        registry = registry_with_test_affect_scheme()
        self.assertTrue(registry.complete)
        matching = [
            spec for spec in registry.type_registry.specs
            if spec.name == OWNER_GRANT_TYPE
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].writer_domain, "d11")
        self.assertFalse(any(
            spec.name == OWNER_GRANT_TYPE
            for spec in registry.registrations["d11"].type_specs
        ))

    async def test_runtime_without_external_authorities_fails_before_opening_business_db(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext(Path(directory), dependencies=None)
            await context.start()
            self.assertEqual(context.health.status, "blocked")
            self.assertIn("external_runtime_authorities", context.health.missing_capabilities)
            self.assertFalse((Path(directory) / "sylanne3.sqlite3").exists())
            await context.stop()
            self.assertEqual(context.health.status, "stopped")

    async def test_authority_bundle_cannot_open_store_without_matching_package_manifest(self) -> None:
        class D02Issuer:
            authorize_resources = lambda *args: None

        class D11Issuer:
            admit_runtime = lambda *args: None

        class Egress:
            begin_handoff = lambda *args: None

        async def ingress(envelope, coordinator):
            return IngressReceipt("rejected")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependencies = RuntimeDependencies(
                authority_attestation_ref="attestation-1",
                package_manifest_sha256="0" * 64,
                deletion_journal=object(),
                migration_authority=object(),
                restore_authority=object(),
                execution_journal_port=types.SimpleNamespace(verify_current_chain=lambda *args: True),
                snapshot_requirements=lambda namespace: None,
                holder="host-1",
                content_fence=lambda *args: None,
                closure_verifier=lambda *args: None,
                d02_issuer=D02Issuer(),
                d11_issuer=D11Issuer(),
                model_egress_authority=Egress(),
                ingress_policy=controlled_ingress_policy,
                ingress_clock=controlled_ingress_clock,
                ingress_handler_factory=lambda coordinator, bootstrap: ingress,
            )
            context = RuntimeContext(
                root / "data", package_root=root, dependencies=dependencies,
                domains=registry_with_test_affect_scheme(),
            )
            await context.start()
            self.assertEqual(context.health.status, "blocked")
            self.assertIn("package_manifest", context.health.missing_capabilities)
            self.assertFalse((root / "data" / "sylanne3.sqlite3").exists())

    async def test_trusted_factory_runs_after_provider_registration_and_rejects_invalid_handler(self) -> None:
        class D02Issuer:
            authorize_resources = lambda *args: None

        class D11Issuer:
            admit_runtime = lambda *args: None

        class Egress:
            begin_handoff = lambda *args: None

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "release-manifest.json"
            manifest.write_bytes(b"controlled-test-manifest")
            seen = []

            def factory(coordinator, bootstrap):
                # The bootstrap is supplied only after the coordinator has all domains.
                lease, ref = coordinator.grant(
                    bootstrap, actor="host", issuer_domain="d06",
                    namespace=NamespaceId("bot", "persona"),
                    domains=("d06", "d11"), activation_generation=0,
                )
                seen.append((coordinator, bootstrap, lease, ref))
                return object()  # A fake dependency cannot make the runtime ready.

            dependencies = RuntimeDependencies(
                authority_attestation_ref="controlled-test-attestation",
                package_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                deletion_journal=object(), migration_authority=object(),
                restore_authority=object(),
                execution_journal_port=types.SimpleNamespace(verify_current_chain=lambda *args: True),
                snapshot_requirements=lambda namespace: None,
                holder="host-1", content_fence=lambda *args: None,
                closure_verifier=lambda *args: None,
                d02_issuer=D02Issuer(), d11_issuer=D11Issuer(),
                model_egress_authority=Egress(),
                ingress_policy=controlled_ingress_policy,
                ingress_clock=controlled_ingress_clock,
                ingress_handler_factory=factory,
            )
            context = RuntimeContext(
                root / "data", package_root=root, dependencies=dependencies,
                domains=registry_with_test_affect_scheme(),
            )
            self.assertEqual((await context.start()).status, "blocked")
            self.assertEqual(context.health.missing_capabilities, ("ingress_handler",))
            self.assertEqual(len(seen), 1)
            self.assertIsNone(context._store)
            self.assertEqual(await context.handle_ingress(await build_astrbot_ingress(Event(), _IngressContext())), IngressReceipt("unavailable"))

            missing_factory = replace(dependencies, ingress_handler_factory=None)
            blocked = RuntimeContext(
                root / "other", package_root=root, dependencies=missing_factory,
                domains=registry_with_test_affect_scheme(),
            )
            self.assertEqual((await blocked.start()).missing_capabilities, ("ingress_handler_factory",))
            self.assertFalse((root / "other" / "sylanne3.sqlite3").exists())

            missing_policy = replace(dependencies, ingress_policy=None)
            blocked_policy = RuntimeContext(
                root / "without-policy", package_root=root, dependencies=missing_policy,
                domains=registry_with_test_affect_scheme(),
            )
            self.assertEqual(
                (await blocked_policy.start()).missing_capabilities,
                ("ingress_policy",),
            )
            self.assertFalse((root / "without-policy" / "sylanne3.sqlite3").exists())

            missing_clock = replace(dependencies, ingress_clock=None)
            blocked_clock = RuntimeContext(
                root / "without-clock", package_root=root, dependencies=missing_clock,
                domains=registry_with_test_affect_scheme(),
            )
            self.assertEqual(
                (await blocked_clock.start()).missing_capabilities,
                ("ingress_clock",),
            )
            self.assertFalse((root / "without-clock" / "sylanne3.sqlite3").exists())

    async def test_real_event_maps_to_bounded_namespace_and_source_identity(self) -> None:
        envelope = await build_astrbot_ingress(Event(), _IngressContext())
        self.assertEqual(envelope.namespace.persona_id, "persona-1")
        self.assertIn("adapter-1", envelope.namespace.bot_id)
        self.assertIn("conversation-1", envelope.conversation_ref)
        self.assertIn("sender-1", envelope.sender_ref)
        self.assertEqual(envelope.message_id, "message-1")
        self.assertEqual(envelope.visibility, "private")
        self.assertEqual(envelope.lineage.source_kind, "reported")
        self.assertEqual(envelope.lineage.content_reality, "external_report")
        self.assertEqual(envelope.lineage.evidence_eligibility, "reported_claim")
        self.assertEqual(len(envelope.lineage.source_ref), 64)

    async def test_future_platform_time_is_unknown_and_receive_time_is_not_fabricated(self) -> None:
        future = time.time() + 3600
        envelope = await build_astrbot_ingress(Event(timestamp=future), _IngressContext())
        self.assertIsNone(envelope.occurred_at)
        self.assertLess(envelope.learned_at, future)

    async def test_host_ingress_maps_to_reported_d06_source_without_lineage_upgrade(self) -> None:
        envelope = await build_astrbot_ingress(Event(), _IngressContext())
        admission = source_admission_from_host(envelope)
        self.assertEqual(admission.source_id, envelope.lineage.source_ref)
        self.assertEqual(admission.text, envelope.text)
        self.assertEqual(admission.source_kind, "reported")
        self.assertEqual(admission.content_reality, "reported")
        self.assertEqual(admission.evidence_eligibility, "reported_claim")
        self.assertEqual(admission.audiences, (envelope.conversation_ref,))

    async def test_d06_ingress_accepts_only_after_coordinator_durable_commit(self) -> None:
        host = await build_astrbot_ingress(Event(), _IngressContext())
        canonical_learned_at = host.learned_at + 1

        class Assembler:
            def __init__(self, *, drift_source_refs=False):
                self.drift_source_refs = drift_source_refs
                self.source_refs = None

            async def assemble(self, envelope, admission, candidate, coordinator):
                source_refs = candidate.qualification.source_refs
                self.source_refs = source_refs
                qualification = replace(
                    candidate.qualification,
                    learned_at=canonical_learned_at,
                )
                if self.drift_source_refs:
                    qualification = replace(qualification, source_refs=("drifted-source",))
                identity = OperationIdentity(
                    "activity-1",
                    None,
                    "attempt-1",
                    "ingress",
                    "operation-1",
                    canonical_digest({"input_refs": list(source_refs)}),
                )
                authority = AuthorityContext(
                    "astrbot-host",
                    "d06",
                    "capability-1",
                    envelope.namespace,
                    ("event",),
                    "context",
                    (envelope.conversation_ref,),
                    "ingress-policy-v1",
                    1,
                )
                command = CommandEnvelope(
                    RUNTIME_SCHEMA,
                    identity,
                    authority,
                    VersionGuard(
                        (), (), 0, 0, "catalogue-1", "scheme-1",
                        "operator-1", "policy-1", (), (), (),
                    ),
                    qualification,
                    source_refs,
                    "budget-lease-1",
                    envelope.learned_at + 30,
                    time.monotonic() + 30,
                    "character-interval-1",
                    (envelope.message_id,),
                )
                provider = D06DomainProvider()
                proposal = DomainProposal(
                    "d06",
                    "d06.contract.v1",
                    provider.descriptor.request_schema_hash,
                    command,
                    (),
                    DependencySet(),
                    ("source-ingress",),
                    (),
                )
                return AuthorizedIngressCommit(
                    DomainBundle(command, (proposal,), (), (), (), (), (), (), ()),
                    object(),
                )

        class Coordinator(GraphCoordinator):
            def __init__(self, status):
                self.status = status
                self.calls = 0
                self.bundle = None

            def commit_domain_bundle(self, bundle, lease):
                self.calls += 1
                self.bundle = bundle
                return CommitReceipt(
                    self.status,
                    bundle.envelope.identity.operation_id,
                    bundle.digest,
                    bundle.envelope.identity.activity_id,
                    None,
                    1 if self.status in {"committed", "duplicate"} else None,
                    (), (), (), (), (),
                )

        committed = Coordinator("committed")
        assembler = Assembler()
        receipt = await build_d06_ingress_handler(assembler)(host, committed)
        self.assertEqual(receipt, IngressReceipt("accepted", "operation-1"))
        self.assertEqual(committed.calls, 1)
        self.assertNotEqual(host.learned_at, canonical_learned_at)
        self.assertEqual(
            committed.bundle.envelope.source_qualification.learned_at,
            canonical_learned_at,
        )
        self.assertEqual(
            committed.bundle.envelope.source_qualification.source_refs,
            assembler.source_refs,
        )

        rejected = Coordinator("rejected")
        receipt = await build_d06_ingress_handler(Assembler())(host, rejected)
        self.assertEqual(receipt, IngressReceipt("rejected"))
        self.assertEqual(rejected.calls, 1)

        drifted = Coordinator("committed")
        with self.assertRaisesRegex(ValueError, "changed source qualification"):
            await build_d06_ingress_handler(Assembler(drift_source_refs=True))(
                host, drifted
            )
        self.assertEqual(drifted.calls, 0)

    async def test_committed_replay_returns_duplicate_without_new_commit(self) -> None:
        host = await build_astrbot_ingress(Event(), _IngressContext())
        identity = ingress_source_identity(host.lineage.source_ref)
        authority = AuthorityContext(
            "astrbot-host", "d06", "capability-1", host.namespace,
            ("event", "activity"), "context", (host.conversation_ref,),
            "ingress-policy-v1", 8,
        )
        session = IngressAuthoritySession(authority, object())
        receipt = CommitReceipt(
            "committed", "host-ingress-" + identity[:32], "b" * 64,
            "ingress-" + identity[:24], None, 1, (), (), (), (), (),
        )
        observation = CanonicalIngressObservation(
            receipt.operation_id, ingress_content_fingerprint(host),
            host.learned_at, "durable:first:" + receipt.operation_id,
        )

        class Coordinator(GraphCoordinator):
            def __init__(self):
                self.receipt = receipt
                self.commit_calls = 0

            def get_operation(self, asserted, lease, operation_id):
                self_outer.assertEqual(asserted, authority)
                self_outer.assertIs(lease, session.lease)
                self_outer.assertEqual(operation_id, receipt.operation_id)
                return self.receipt

            def commit_domain_bundle(self, bundle, lease):
                self.commit_calls += 1
                raise AssertionError("committed replay must not recommit")

        class Assembler:
            def __init__(self, replay):
                self.replay = replay

            async def assemble(self, envelope, admission, candidate, coordinator):
                return self.replay

        self_outer = self
        coordinator = Coordinator()
        replay = CommittedIngressReplay(receipt, observation, session)
        result = await build_d06_ingress_handler(Assembler(replay))(
            host, coordinator)
        self.assertEqual(result, IngressReceipt("duplicate", receipt.operation_id))
        self.assertEqual(coordinator.commit_calls, 0)

        forged = CommittedIngressReplay(
            replace(receipt, operation_digest="f" * 64), observation, session)
        with self.assertRaisesRegex(ValueError, "no current coordinator receipt"):
            await build_d06_ingress_handler(Assembler(forged))(
                host, coordinator)
        with self.assertRaisesRegex(ValueError, "scope or content"):
            await build_d06_ingress_handler(Assembler(replay))(
                replace(host, text="changed"), coordinator)
        self.assertEqual(coordinator.commit_calls, 0)

    async def test_unmapped_media_is_rejected_before_runtime_admission(self) -> None:
        event = Event(text="caption")
        event.message_obj.message = [Image.fromURL("https://example.invalid/a.png")]
        with self.assertRaisesRegex(ValueError, "media"):
            await build_astrbot_ingress(event, _IngressContext())

    async def test_real_astrbot_lifecycle_registers_all_message_ingress_but_does_not_claim_when_blocked(self) -> None:
        module = load_plugin_module()
        self.assertTrue(issubclass(module.Sylanne3Plugin, Star))
        handlers = [
            handler for handler in star_handlers_registry
            if handler.handler_module_path == MODULE and handler.handler_name == "ingress"
        ]
        self.assertEqual(len(handlers), 1)
        self.assertTrue(any(isinstance(item, EventMessageTypeFilter) for item in handlers[0].event_filters))

        with tempfile.TemporaryDirectory() as directory:
            original = StarTools.__dict__["get_data_dir"]
            StarTools.get_data_dir = classmethod(lambda cls, plugin_name=None: Path(directory))
            try:
                plugin = module.Sylanne3Plugin(Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None), {"enabled": True})
                with patch.object(module, "assemble_v2_installation", side_effect=FileNotFoundError):
                    await plugin.initialize()
                event = Event()
                await plugin.ingress(event)
                self.assertFalse(event.is_stopped())
                self.assertEqual(event.sent, [])
                self.assertEqual(plugin.runtime_health.status, "enrollment_required")
                await plugin.terminate()
                self.assertEqual(plugin.runtime_health.status, "stopped")
            finally:
                StarTools.get_data_dir = original

    async def test_controlled_ready_runtime_receipt_is_the_only_event_takeover_boundary(self) -> None:
        module = load_plugin_module()

        class ControlledRuntime:
            def __init__(self):
                self.envelopes = []

            async def handle_ingress(self, envelope):
                self.envelopes.append(envelope)
                return IngressReceipt("accepted", "operation-1")

        plugin = module.Sylanne3Plugin(
            Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
            {"enabled": True},
        )
        plugin.context = _IngressContext()
        controlled = ControlledRuntime()
        plugin._runtime = controlled
        plugin.runtime_health = RuntimeHealth("ready")
        event = Event()
        await plugin.ingress(event)
        self.assertTrue(event.is_stopped())
        self.assertEqual(len(controlled.envelopes), 1)
        self.assertEqual(controlled.envelopes[0].lineage.source_ref.__len__(), 64)

    async def test_stock_authority_client_requires_enrollment_and_ignores_self_signed_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = AuthorityClient(
                AuthoritySelection("default"),
                package_root=ROOT,
                data_dir=Path(directory),
            )
            status = await client.status()
            self.assertEqual(status.state, "enrollment_required")
            self.assertIsNone(await client.capability_grant())

    def test_authority_profile_is_a_selector_not_an_endpoint_or_path(self) -> None:
        for value in ("../authority", "https://authority.invalid", "", "a" * 65):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AuthoritySelection(value)

    async def test_chat_configuration_cannot_self_sign_authority_or_activation(self) -> None:
        module = load_plugin_module()
        with tempfile.TemporaryDirectory() as directory:
            original = StarTools.__dict__["get_data_dir"]
            StarTools.get_data_dir = classmethod(lambda cls, plugin_name=None: Path(directory))
            try:
                plugin = module.Sylanne3Plugin(
                    Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
                    {
                        "enabled": True,
                        "authority_profile": "default",
                        "authority_private_key": "self-signed",
                        "package_manifest_sha256": "0" * 64,
                        "activation_generation": 999,
                    },
                )
                with patch.object(module, "assemble_v2_installation", side_effect=FileNotFoundError):
                    await plugin.initialize()
                self.assertEqual(plugin.runtime_health.status, "enrollment_required")
                self.assertFalse((Path(directory) / "sylanne3.sqlite3").exists())
            finally:
                StarTools.get_data_dir = original

    async def test_disabled_plugin_never_loads_admin_profile(self) -> None:
        module = load_plugin_module()
        plugin = module.Sylanne3Plugin(
            Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
            {"enabled": False},
        )
        with patch.object(module, "assemble_v2_installation") as load:
            await plugin.initialize()
        load.assert_not_called()
        self.assertEqual(plugin.runtime_health.status, "limited")
        self.assertEqual(plugin.runtime_health.missing_capabilities, ("disabled",))

    async def test_admin_profile_failures_are_sanitized_before_runtime_bootstrap(self) -> None:
        module = load_plugin_module()
        for failure, status, missing in (
            (FileNotFoundError("secret profile path"), "enrollment_required", "authority_profile"),
            (PermissionError("secret key path"), "blocked", "authority_profile_integrity"),
            (ValueError("secret endpoint"), "blocked", "authority_profile_integrity"),
            (module.AuthorityProfileUnavailable("secret platform path"), "blocked", "authority_profile_verification"),
        ):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                with patch.object(StarTools, "get_data_dir", return_value=Path(directory)):
                    plugin = module.Sylanne3Plugin(
                        Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None, None),
                        {"enabled": True},
                    )
                    with patch.object(module, "assemble_v2_installation", side_effect=failure), \
                            patch.object(module, "RuntimeContext") as runtime:
                        await plugin.initialize()
                    runtime.assert_not_called()
                    self.assertEqual(plugin.runtime_health.status, status)
                    self.assertEqual(plugin.runtime_health.missing_capabilities, (missing,))
                    self.assertNotIn("secret", plugin.runtime_health.detail)
                    self.assertIsNone(plugin._runtime)
                    self.assertFalse((Path(directory) / "sylanne3.sqlite3").exists())

    @unittest.skipUnless(platform.system() == "Windows", "Windows profile verifier boundary")
    async def test_windows_missing_admin_profile_requires_enrollment_without_runtime(self) -> None:
        module = load_plugin_module()
        missing_profile = "missing-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(StarTools, "get_data_dir", return_value=Path(directory)), \
                    patch.object(module, "RuntimeContext") as runtime:
                plugin = module.Sylanne3Plugin(
                    Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
                    {"enabled": True, "authority_profile": missing_profile},
                )
                await plugin.initialize()
            runtime.assert_not_called()
            self.assertEqual(plugin.runtime_health.status, "enrollment_required")
            self.assertEqual(
                plugin.runtime_health.missing_capabilities,
                ("authority_profile",),
            )
            self.assertIsNone(plugin._runtime)
            self.assertFalse((Path(directory) / "sylanne3.sqlite3").exists())

    async def test_verified_v2_startup_orders_installation_scheme_and_worker(self) -> None:
        module = load_plugin_module()
        order = []
        registry = object()
        policy = types.SimpleNamespace(
            manifest_digest="a" * 64,
            namespace=NamespaceId("bot", "persona"),
            digest_payload=lambda: {"installation_id": "installation-1", "namespace": {
                "bot_id": "bot", "persona_id": "persona"}},
        )
        installation = types.SimpleNamespace(
            installation_policy=policy,
            available_cpu_features=frozenset({"avx2"}),
        )

        async def assemble(profile_id, *, package_root, data_dir):
            order.append("installation")
            self.assertEqual(profile_id, "installed")
            self.assertEqual(package_root, module.PACKAGE_ROOT)
            self.assertEqual(data_dir, resolved_dir)
            return installation

        def load_scheme(package_root, digest, *, available_cpu_features):
            order.append("scheme")
            self.assertEqual(package_root, module.PACKAGE_ROOT)
            self.assertEqual(digest, "a" * 64)
            self.assertEqual(available_cpu_features, frozenset({"avx2"}))
            return types.SimpleNamespace(scheme=object(), registry=registry)

        class ControlledRuntime:
            def __init__(self, data_dir, *, package_root, dependencies, domains):
                order.append("context")
                self.arguments = (data_dir, package_root, dependencies, domains)

            async def start_v2(self, assembled):
                order.append("start_v2")
                self_outer.assertIs(assembled, installation)
                return RuntimeHealth("limited", ("namespace_activation",), "internal path")

            async def provision_installed_namespace(self, operation_id):
                order.append(("provision", operation_id))
                self.health = RuntimeHealth("limited", ("product_ingress", "dispatch"))
                return object()

        self_outer = self
        with tempfile.TemporaryDirectory() as directory:
            resolved_dir = await asyncio.to_thread(Path(directory).resolve)
            with patch.object(StarTools, "get_data_dir", return_value=Path(directory)), \
                    patch.object(module, "assemble_v2_installation", side_effect=assemble), \
                    patch.object(module, "load_verified_affect_scheme", side_effect=load_scheme), \
                    patch.object(module, "RuntimeContext", ControlledRuntime):
                plugin = module.Sylanne3Plugin(
                    Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None, None),
                    {"enabled": True, "authority_profile": "installed"},
                )
                await plugin.initialize()
            self.assertEqual(order[:4], ["installation", "scheme", "context", "start_v2"])
            self.assertEqual(order[4], (
                "provision", "namespace-provision:" + canonical_digest(policy.digest_payload()),
            ))
            self.assertEqual(plugin._runtime.arguments, (
                resolved_dir, module.PACKAGE_ROOT, None, registry,
            ))
            self.assertEqual(plugin.runtime_health.status, "limited")
            self.assertEqual(plugin.runtime_health.missing_capabilities,
                             ("product_ingress", "dispatch"))
            self.assertEqual(plugin.runtime_health.detail, "")
            event = Event()
            await plugin.ingress(event)
            self.assertFalse(event.is_stopped())
            self.assertFalse((Path(directory) / "sylanne3.sqlite3").exists())

    async def test_namespace_provision_hold_keeps_host_blocked(self) -> None:
        module = load_plugin_module()
        policy = types.SimpleNamespace(
            manifest_digest="a" * 64,
            namespace=NamespaceId("bot", "persona"),
            digest_payload=lambda: {"installation_id": "installation-1"},
        )
        installation = types.SimpleNamespace(
            installation_policy=policy, available_cpu_features=None,
        )
        operation_ids = []

        class ControlledRuntime:
            def __init__(self, data_dir, *, package_root, dependencies, domains):
                pass

            async def start_v2(self, assembled):
                return RuntimeHealth("limited", ("namespace_activation",))

            async def provision_installed_namespace(self, operation_id):
                operation_ids.append(operation_id)
                self.health = RuntimeHealth(
                    "blocked", ("namespace_activation",), "HOLD pending exact attempt",
                )
                raise RuntimeError("HOLD pending exact attempt")

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(StarTools, "get_data_dir", return_value=Path(directory)), \
                    patch.object(module, "assemble_v2_installation",
                                 new=AsyncMock(return_value=installation)), \
                    patch.object(module, "load_verified_affect_scheme",
                                 return_value=types.SimpleNamespace(registry=object())), \
                    patch.object(module, "RuntimeContext", ControlledRuntime):
                plugin = module.Sylanne3Plugin(
                    Context(asyncio.Queue(), {}, None, None, None, None,
                            None, None, None, None, None, None),
                    {"enabled": True},
                )
                await plugin.initialize()
                first_id = operation_ids[0]
                await plugin.initialize()
                self.assertEqual(operation_ids, [first_id, first_id])
                self.assertEqual(plugin.runtime_health.status, "blocked")
                self.assertEqual(plugin.runtime_health.detail, "HOLD pending exact attempt")
                event = Event()
                await plugin.ingress(event)
                self.assertFalse(event.is_stopped())

    async def test_d04_verification_failure_blocks_before_runtime_without_leaking_detail(self) -> None:
        module = load_plugin_module()
        installation = types.SimpleNamespace(
            installation_policy=types.SimpleNamespace(manifest_digest="a" * 64),
            available_cpu_features=None,
        )
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(StarTools, "get_data_dir", return_value=Path(directory)), \
                    patch.object(module, "assemble_v2_installation", new=AsyncMock(return_value=installation)), \
                    patch.object(module, "load_verified_affect_scheme",
                                 side_effect=ValueError("secret package path")), \
                    patch.object(module, "RuntimeContext") as runtime:
                plugin = module.Sylanne3Plugin(
                    Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None, None),
                    {"enabled": True},
                )
                await plugin.initialize()
            runtime.assert_not_called()
            self.assertEqual(plugin.runtime_health.status, "blocked")
            self.assertEqual(plugin.runtime_health.missing_capabilities,
                             ("affect_scheme_verification",))
            self.assertEqual(plugin.runtime_health.detail, "")
            self.assertFalse((Path(directory) / "sylanne3.sqlite3").exists())

    async def test_v2_bootstrap_cannot_publish_ready_from_runtime_result(self) -> None:
        module = load_plugin_module()
        installation = types.SimpleNamespace(
            installation_policy=types.SimpleNamespace(manifest_digest="a" * 64),
            available_cpu_features=None,
        )
        registry = object()
        runtime = types.SimpleNamespace(start_v2=AsyncMock(return_value=RuntimeHealth("ready")))
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(StarTools, "get_data_dir", return_value=Path(directory)), \
                    patch.object(module, "assemble_v2_installation", new=AsyncMock(return_value=installation)), \
                    patch.object(module, "load_verified_affect_scheme",
                                 return_value=types.SimpleNamespace(scheme=object(), registry=registry)), \
                    patch.object(module, "RuntimeContext", return_value=runtime):
                plugin = module.Sylanne3Plugin(
                    Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
                    {"enabled": True},
                )
                await plugin.initialize()
            runtime.start_v2.assert_awaited_once_with(installation)
            self.assertEqual(plugin.runtime_health.status, "blocked")
            self.assertEqual(plugin.runtime_health.missing_capabilities,
                             ("runtime_bootstrap",))
            event = Event()
            await plugin.ingress(event)
            self.assertFalse(event.is_stopped())

    async def test_ready_host_does_not_take_over_unknown_sender_identity(self) -> None:
        module = load_plugin_module()

        class ControlledRuntime:
            called = False

            async def handle_ingress(self, envelope):
                self.called = True
                return IngressReceipt("accepted", "operation-unknown")

        plugin = module.Sylanne3Plugin(
            Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
            {"enabled": True},
        )
        plugin.context = _IngressContext()
        runtime = ControlledRuntime()
        plugin._runtime = runtime
        plugin.runtime_health = RuntimeHealth("ready")
        event = Event()
        event.message_obj.sender = MessageMember("", "Unknown")
        await plugin.ingress(event)
        self.assertFalse(event.is_stopped())
        self.assertFalse(runtime.called)


if __name__ == "__main__":
    unittest.main()
