"""Installed migration identities and durable pairing revocation."""

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.installed_migration_pairing import (
    AdministratorMigrationPairingV1, InstalledMigrationPairingRegistry,
)
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.v2_migration_rpc import (
    MigrationRpcHandlerV2, to_wire,
)
from test_v2_migration_rpc import (
    CHANNEL, SOURCE, TARGET, _call, _setup,
)
from test_v2_migration_local_state import _close


def _registry(bundle, plan, *, source=SOURCE, target=TARGET):
    core = bundle[3]
    pairing = AdministratorMigrationPairingV1(
        "ns-a", plan.namespace_id,
        source.certificate_sha256, "profile-a", "holder-source", "install-source",
        target.certificate_sha256, "profile-a", "holder-target", "install-target",
    )
    installations = {
        (source.certificate_sha256, "profile-a"):
            AdministratorInstallationV2("install-source", "holder-source",
                                         "publisher-a", "v2", "a" * 64),
        (target.certificate_sha256, "profile-a"):
            AdministratorInstallationV2("install-target", "holder-target",
                                         "publisher-a", "v2", "a" * 64),
    }
    bindings = {
        (source.certificate_sha256, "profile-a", plan.namespace_id): "ns-a",
        (target.certificate_sha256, "profile-a", plan.namespace_id): "ns-a",
    }
    return InstalledMigrationPairingRegistry(core, {"ns-a": pairing},
                                             installations, bindings)


def test_installed_pairing_controls_begin_replay_recovery_and_revoke(tmp_path):
    bundle, _, plan = _setup(tmp_path)
    try:
        registry = _registry(bundle, plan)
        migration = bundle[1]
        migration._pairing_verifier = registry.verify_pairing
        handler = MigrationRpcHandlerV2(
            {"ns-a": migration},
            resolve_management_binding=registry.resolve_management_binding)
        command = {"request_id": "begin-a", "plan": to_wire(plan)}
        with pytest.raises(AuthorityUnavailable):
            _call(handler, SOURCE, "begin_transfer", **command)
        registry.install_schema("admin")
        registry.register("admin", "ns-a")
        assert registry.verify_pairing(
            SOURCE, "mtls:sha256:" + SOURCE.certificate_sha256,
            plan, "begin") is True
        assert registry.verify_pairing(
            TARGET, "mtls:sha256:" + TARGET.certificate_sha256,
            plan, "begin") is False
        assert registry.resolve_management_binding(
            SOURCE, "profile-a", CHANNEL, "ns-a").role == "source"
        assert registry.resolve_management_binding(
            TARGET, "profile-a", CHANNEL, "ns-a").role == "target"
        assert registry.resolve_management_binding(
            SOURCE, "other-profile", CHANNEL, "ns-a") is None
        assert registry.resolve_management_binding(
            SOURCE, "profile-a", "bad", "ns-a") is None
        first = _call(handler, SOURCE, "begin_transfer", **command)
        assert first["result"]["status"]["phase"] == "begun"
        assert _call(handler, SOURCE, "begin_transfer", **command) == first
        registry.revoke("admin", "ns-a")
        assert registry.verify_pairing(
            SOURCE, "mtls:sha256:" + SOURCE.certificate_sha256,
            plan, "begin") is False
        with pytest.raises(AuthorityUnavailable):
            _call(handler, SOURCE, "begin_transfer", **command)
        with pytest.raises(AuthorityUnavailable):
            _call(handler, TARGET, "recover_transfer", transfer_id=plan.transfer_id)
        with pytest.raises(AuthorityUnavailable):
            registry.register("admin", "ns-a")
        reopened = _registry(bundle, plan)
        assert reopened.resolve_management_binding(
            SOURCE, "profile-a", CHANNEL, "ns-a") is None
    finally:
        _close(bundle)


def test_registration_requires_exact_installed_namespace_and_administrator(tmp_path):
    bundle, _, plan = _setup(tmp_path)
    try:
        registry = _registry(bundle, plan)
        core = bundle[3]
        prior_authorizer = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            credential == "admin" if action.startswith("migration_pair_")
            else prior_authorizer(credential, action, namespace, holder)
        )
        with pytest.raises(AuthorityUnavailable):
            registry.install_schema(SOURCE)
        registry.install_schema("admin")
        with pytest.raises(AuthorityUnavailable):
            registry.register(SOURCE, "ns-a")
        registry.register("admin", "ns-a")
        with pytest.raises(AuthorityUnavailable):
            registry.revoke(TARGET, "ns-a")
        assert registry.resolve_management_binding(
            SOURCE, "profile-a", CHANNEL, "ns-a") is not None
        wrong_binding = {
            (SOURCE.certificate_sha256, "profile-a", plan.namespace_id): "other",
            (TARGET.certificate_sha256, "profile-a", plan.namespace_id): "ns-a",
        }
        pairing = registry._pairings["ns-a"]
        installations = {
            (SOURCE.certificate_sha256, "profile-a"):
                AdministratorInstallationV2("install-source", "holder-source",
                                             "publisher-a", "v2", "a" * 64),
            (TARGET.certificate_sha256, "profile-a"):
                AdministratorInstallationV2("install-target", "holder-target",
                                             "publisher-a", "v2", "a" * 64),
        }
        with pytest.raises(AuthorityUnavailable, match="installed namespace"):
            InstalledMigrationPairingRegistry(bundle[3], {"ns-a": pairing},
                                             installations, wrong_binding)
    finally:
        _close(bundle)
