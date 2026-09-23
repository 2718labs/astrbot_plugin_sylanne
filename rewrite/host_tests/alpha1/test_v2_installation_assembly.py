import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from sylanne3.host.authority_client import AuthorityClientStatus
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.v2_installation import assemble_v2_installation
from sylanne3.runtime_contracts import InstallationGrantV2


class V2InstallationAssemblyTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_identity_creates_worker_port_factory_and_closes_probe(self):
        digest = "a" * 64
        profile = SimpleNamespace(
            profile_id="installed", expected_authority_id="authority",
            prepared_ssl_context=object(),
        )
        policy = SimpleNamespace(
            expected_authority_id="authority", installation_id="install",
            administrator_holder="holder", manifest_digest=digest,
        )
        bundle = SimpleNamespace(
            tls_profile=profile, installation_policy=policy, d11_signing_key=b"k" * 32,
        )
        grant = InstallationGrantV2(
            authority_id="authority", subject="mtls:sha256:peer",
            administrator_holder="holder", installation_id="install",
            manifest_digest=digest, publisher_policy_ref="publisher-policy",
            service_capability_version="v2", channel_binding_sha256="b" * 64,
        )
        transport = MagicMock()
        transport.close = AsyncMock()
        client = MagicMock()
        client.status_v2 = AsyncMock(return_value=AuthorityClientStatus("paired", "authority"))
        client.installation_grant_v2 = AsyncMock(return_value=grant)
        package = InstalledPackageVerification(True, "verified", digest, "3.0.0-alpha1", "formal-alpha1")
        with (patch("sylanne3.host.v2_installation.load_admin_installation_bundle", return_value=bundle),
              patch("sylanne3.host.v2_installation.verify_installed_package", return_value=package),
              patch("sylanne3.host.v2_installation.MtlsAuthorityTransport", return_value=transport),
              patch("sylanne3.host.v2_installation.AuthorityClient", return_value=client),
              patch("sylanne3.host.v2_installation.V2FencePort") as port_type):
            assembled = await assemble_v2_installation(
                "installed", package_root=Path("G:/package"), data_dir=Path("G:/data"),
                available_cpu_features=frozenset({"avx2"}),
            )
            self.assertIs(assembled.installation_grant, grant)
            self.assertIs(assembled.installation_policy, policy)
            self.assertEqual(assembled.d11_signing_key, b"k" * 32)
            self.assertEqual(assembled.package_root, Path("G:/package"))
            self.assertEqual(assembled.data_dir, Path("G:/data"))
            self.assertEqual(assembled.available_cpu_features, frozenset({"avx2"}))
            port_type.assert_not_called()
            await asyncio.to_thread(assembled.fence_port_factory)
            request, profiles, selected_grant = port_type.call_args.args
            self.assertEqual(request.publisher_package.manifest_sha256, digest)
            self.assertEqual(request.package_root, assembled.package_root)
            self.assertEqual(request.data_dir, assembled.data_dir)
            self.assertEqual(profiles, {"installed": profile})
            self.assertIs(selected_grant, grant)
            transport.close.assert_awaited_once()

    async def test_installation_mismatch_fails_closed_and_closes_probe(self):
        digest = "a" * 64
        bundle = SimpleNamespace(
            tls_profile=SimpleNamespace(
                profile_id="installed", expected_authority_id="authority",
                prepared_ssl_context=object(),
            ),
            installation_policy=SimpleNamespace(
                expected_authority_id="authority", installation_id="install",
                administrator_holder="holder", manifest_digest=digest,
            ),
            d11_signing_key=b"k" * 32,
        )
        grant = InstallationGrantV2(
            authority_id="authority", subject="mtls:sha256:peer",
            administrator_holder="other-holder", installation_id="install",
            manifest_digest=digest, publisher_policy_ref="publisher-policy",
            service_capability_version="v2", channel_binding_sha256="b" * 64,
        )
        transport = MagicMock()
        transport.close = AsyncMock()
        client = MagicMock()
        client.status_v2 = AsyncMock(return_value=AuthorityClientStatus("paired", "authority"))
        client.installation_grant_v2 = AsyncMock(return_value=grant)
        package = InstalledPackageVerification(True, "verified", digest, "3.0.0-alpha1", "formal-alpha1")
        with (patch("sylanne3.host.v2_installation.load_admin_installation_bundle", return_value=bundle),
              patch("sylanne3.host.v2_installation.verify_installed_package", return_value=package),
              patch("sylanne3.host.v2_installation.MtlsAuthorityTransport", return_value=transport),
              patch("sylanne3.host.v2_installation.AuthorityClient", return_value=client)):
            with self.assertRaisesRegex(RuntimeError, "differs from administrator"):
                await assemble_v2_installation(
                    "installed", package_root=Path("G:/package"), data_dir=Path("G:/data"),
                )
            transport.close.assert_awaited_once()
