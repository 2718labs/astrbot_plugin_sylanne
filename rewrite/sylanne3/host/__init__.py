from .authority_client import (
    AuthorityCapabilityGrant,
    AuthorityClient,
    AuthorityClientStatus,
    AuthorityEnrollmentGrant,
    AuthoritySelection,
)
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from .ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from .ingress_assembler import (
    CanonicalIngressObservation,
    IngressAuthoritySession,
    IngressAssemblyRequest,
    IngressObservationAuthority,
    IngressObservationContext,
    IngressRuntimeAuthorization,
    LocalIngressAssembler,
    TrustedIngressIssuer,
    ingress_content_fingerprint,
)
from .d06_ingress import (
    AuthorizedIngressCommit,
    IngressBundleAssembler,
    build_d06_ingress_handler,
    source_admission_from_host,
)
from .v2_installation import V2InstallationAssembly, assemble_v2_installation


def __getattr__(name: str):
    if name in {"AstrBotIngressError", "build_astrbot_ingress"}:
        from .astrbot import AstrBotIngressError, build_astrbot_ingress

        return {"AstrBotIngressError": AstrBotIngressError,
                "build_astrbot_ingress": build_astrbot_ingress}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

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
