from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.installed_c04_composition import (
    compose_host_installed_c04_executor_v2,
)
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.runtime_contracts import NamespaceId


class InstalledC04CompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace = NamespaceId("bot", "persona")
        self.bridge = SimpleNamespace(namespace=namespace_ref(self.namespace))
        self.package_root = Path.cwd() / "installed-package"
        self.graph_db_path = Path.cwd() / "graph.sqlite3"
        self.credential = object()

    def compose(self):
        return compose_host_installed_c04_executor_v2(
            profile_id="installed", bridge=self.bridge,
            namespace=self.namespace, graph_db_path=self.graph_db_path,
            package_root=self.package_root, credential=self.credential)

    def test_missing_external_pin_rejected_before_package_or_key(self) -> None:
        policy = SimpleNamespace(namespace=self.namespace, manifest_digest=None)
        with (patch("sylanne3.host.installed_c04_composition.load_admin_installation_policy",
                    return_value=policy),
              patch("sylanne3.host.installed_c04_composition.verify_installed_package") as verify,
              patch("sylanne3.host.installed_c04_composition.load_admin_c04_signing_key") as key):
            with self.assertRaisesRegex(AuthorityUnavailable, "manifest pin"):
                self.compose()
            verify.assert_not_called()
            key.assert_not_called()

    def test_diagnostic_package_rejected_before_key_or_factory(self) -> None:
        pin = "a" * 64
        policy = SimpleNamespace(namespace=self.namespace, manifest_digest=pin)
        diagnostic = InstalledPackageVerification(
            True, "verified", pin, "3.0.0-alpha1", "diagnostic")
        with (patch("sylanne3.host.installed_c04_composition.load_admin_installation_policy",
                    return_value=policy),
              patch("sylanne3.host.installed_c04_composition.verify_installed_package",
                    return_value=diagnostic) as verify,
              patch("sylanne3.host.installed_c04_composition.load_admin_c04_signing_key") as key,
              patch("sylanne3.host.installed_c04_composition.compose_installed_c04_executor_v2") as factory):
            with self.assertRaisesRegex(AuthorityUnavailable, "formal installed package"):
                self.compose()
            verify.assert_called_once_with(self.package_root, pin)
            key.assert_not_called()
            factory.assert_not_called()

    def test_formal_pin_key_and_current_context_reach_authority_factory(self) -> None:
        pin = "a" * 64
        policy = SimpleNamespace(namespace=self.namespace, manifest_digest=pin)
        formal = InstalledPackageVerification(
            True, "verified", pin, "3.0.0-alpha1", "formal-alpha1")
        with (patch("sylanne3.host.installed_c04_composition.load_admin_installation_policy",
                    return_value=policy),
              patch("sylanne3.host.installed_c04_composition.verify_installed_package",
                    return_value=formal),
              patch("sylanne3.host.installed_c04_composition.load_admin_c04_signing_key",
                    return_value=b"k" * 32) as key,
              patch("sylanne3.host.installed_c04_composition.compose_installed_c04_executor_v2",
                    return_value=("service", "executor")) as factory):
            self.assertEqual(self.compose(), ("service", "executor"))
            key.assert_called_once_with("installed")
            factory.assert_called_once_with(
                bridge=self.bridge, namespace=self.namespace,
                graph_db_path=self.graph_db_path, package_root=self.package_root,
                trusted_manifest_sha256=pin,
                component_signing_key=b"k" * 32, credential=self.credential)
