"""Closed locator for a separately installed maintenance console identity."""
from dataclasses import dataclass, asdict
from urllib.parse import urlsplit

from .contract import identifier
from ..runtime_contracts import NamespaceId, namespace_ref

MAINTENANCE_CONSOLE_PROTOCOL_V1 = 'sylanne3.maintenance-console.v1'
MAINTENANCE_CONSOLE_METHOD_V1 = 'maintenance_console_v1'


@dataclass(frozen=True, slots=True)
class MaintenanceConsoleBindingV1:
    authority_id: str
    installation_id: str
    authority_namespace: str
    console_profile_id: str
    console_cert_sha256: str
    package_manifest_digest: str
    origin: str
    namespace: NamespaceId
    root_role_binding_digest: str
    transport_profile: str

    def __post_init__(self):
        for name in ('authority_id', 'installation_id', 'authority_namespace', 'console_profile_id'):
            identifier(getattr(self, name), name)
        for name in ('console_cert_sha256', 'package_manifest_digest', 'root_role_binding_digest'):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('maintenance console requires exact SHA256 identity: ' + name)
        if type(self.namespace) is not NamespaceId or namespace_ref(self.namespace) != self.authority_namespace:
            raise ValueError('maintenance console namespace binding differs')
        parsed = urlsplit(self.origin)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment
                or self.origin != parsed.scheme + '://' + parsed.netloc):
            raise ValueError('maintenance console requires its exact configured Origin')
        parsed.port
        if self.transport_profile != ('full_http' if parsed.scheme == 'http' else 'https'):
            raise ValueError('maintenance console transport must explicitly match its Origin')

    def request_v1(self):
        return dict(protocol=MAINTENANCE_CONSOLE_PROTOCOL_V1, console_profile_id=self.console_profile_id,
            authority_id=self.authority_id, installation_id=self.installation_id,
            authority_namespace=self.authority_namespace, namespace=asdict(self.namespace),
            package_manifest_digest=self.package_manifest_digest,
            root_role_binding_digest=self.root_role_binding_digest, origin=self.origin)
