"""Retired half-flow for first-ingress encoding.

New work must keep its V3 worker lease open through original egress, cost,
worker result read, and the later C02 adoption. The old single-call runner
cannot satisfy that lifecycle and therefore remains HOLD.
"""

from __future__ import annotations

from astrbot.api.star import Context

from ..runtime_context import RuntimeContext
from .ingress import HostIngressEnvelope, IngressReceipt
from .model_egress_executor import FrozenEncodingEgressResult
from .v2_installation import V2InstallationAssembly


async def run_installed_first_ingress_encoding_v2(
    runtime: RuntimeContext, installation: V2InstallationAssembly, *,
    context: Context, trusted_umo: str, envelope: HostIngressEnvelope,
    receipt: IngressReceipt,
) -> FrozenEncodingEgressResult | None:
    """Hold without acquiring a job, pairing Authority, or dispatching a model."""
    return None


__all__ = ("run_installed_first_ingress_encoding_v2",)
