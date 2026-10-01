"""Host adapters loaded on demand to avoid domain/profile import cycles."""
from importlib import import_module

_EXPORT_GROUPS = {
    "authority_client": ("AuthorityCapabilityGrant", "AuthorityClient", "AuthorityClientStatus", "AuthorityEnrollmentGrant", "AuthoritySelection"),
    "mtls_transport": ("AuthorityTlsProfile", "MtlsAuthorityTransport"),
    "ingress": ("HostIngressEnvelope", "IngressReceipt", "SourceLineage"),
    "ingress_assembler": ("CanonicalIngressObservation", "IngressAuthoritySession", "IngressAssemblyRequest", "IngressObservationAuthority", "IngressObservationContext", "IngressRuntimeAuthorization", "LocalIngressAssembler", "TrustedIngressIssuer", "ingress_content_fingerprint"),
    "d06_ingress": ("AuthorizedIngressCommit", "IngressBundleAssembler", "build_d06_ingress_handler", "source_admission_from_host"),
    "v2_installation": ("V2InstallationAssembly", "assemble_v2_installation"),
    "astrbot": ("AstrBotIngressError", "build_astrbot_ingress"),
}
_EXPORTS = {name: module for module, names in _EXPORT_GROUPS.items() for name in names}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module("." + _EXPORTS[name], __name__), name)
    globals()[name] = value
    return value


__all__ = (
    "AstrBotIngressError",
    "AuthorityClient",
    "AuthorityClientStatus",
    "AuthorityEnrollmentGrant",
    "AuthorityCapabilityGrant",
    "AuthoritySelection",
    "AuthorityTlsProfile",
    "AuthorizedIngressCommit",
    "V2InstallationAssembly",
    "HostIngressEnvelope",
    "IngressReceipt",
    "IngressBundleAssembler",
    "CanonicalIngressObservation",
    "IngressAuthoritySession",
    "IngressAssemblyRequest",
    "IngressRuntimeAuthorization",
    "IngressObservationAuthority",
    "IngressObservationContext",
    "MtlsAuthorityTransport",
    "SourceLineage",
    "LocalIngressAssembler",
    "TrustedIngressIssuer",
    "build_astrbot_ingress",
    "build_d06_ingress_handler",
    "assemble_v2_installation",
    "source_admission_from_host",
    "ingress_content_fingerprint",
)
