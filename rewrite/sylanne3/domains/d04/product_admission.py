"""D04's unsigned product-admission premise over one current read frame.

The caller can recompute this premise, but cannot use it to authorize a
product readout. W01 must obtain every row under one Authority fence, verify
the durable D12 compiled original and installed D04 Scheme, then adopt it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...domains.d12.scheme_command import (
    D12CompiledSchemeV1, compiled_scheme_digest_v1,
)
from ...domains.d12.types import ActiveSchemeHeadV1, active_scheme_head_key
from ...graph_types import GraphSnapshot, GraphVersion
from ...native_runtime.d04_mixed_readout_preflight import (
    D04MixedReadoutPreflight, preflight_d04_mixed_readout,
)
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...native_runtime.tanh_asset_readout import D04ConditionalTanhReadoutMath
from ...runtime.authoritative_coupling_snapshot import D04UnsignedCouplingSnapshotCandidateV1
from ...runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from .product_issuer import D04CurrentProductReadFrameV1
from .product_readout import AffectiveReadoutCandidate, D04ReadoutHold, _inherited_radius


@dataclass(frozen=True, slots=True)
class D04SchemeOriginalClaimV1:
    """Claim to be checked against W01's durable D12 original, never authority."""

    head_version: GraphVersion
    head_value_digest: str
    compiled_original: D12CompiledSchemeV1
    installed_scheme_asset_sha256: str
    scheme_value_digest: str
    graph_incarnation: str
    graph_revision: int
    status: str = "claim_requires_w01_durable_original_verification"

    def __post_init__(self) -> None:
        if self.status != "claim_requires_w01_durable_original_verification":
            raise ValueError("Scheme original claim cannot grant adoption")


@dataclass(frozen=True, slots=True)
class D04ProductAdmissionCandidateV1:
    namespace: NamespaceId
    graph_incarnation: str
    graph_revision: int
    query_epoch: QueryEpoch
    access_epoch: int
    delete_epoch: int
    graph_version_digest: str
    numeric_inventory_digest: str
    source_closure_digest: str
    readout_proof_digest: str
    scheme_head_version: GraphVersion
    claimed_compiled_original_digest: str
    installed_scheme_asset_sha256: str
    numeric_error_bound: float
    read_versions: tuple[GraphVersion, ...]
    status: str = "hold_for_w01_current_fence_scheme_original_and_product_adoption"

    def __post_init__(self) -> None:
        if self.status != "hold_for_w01_current_fence_scheme_original_and_product_adoption":
            raise ValueError("D04 product premise cannot grant adoption")


def compile_d04_product_admission_candidate(
    *, graph: D04UnsignedCouplingSnapshotCandidateV1,
    numeric_snapshot: GraphSnapshot, frame: D04CurrentProductReadFrameV1,
    asset: D04LoadedTanhReadoutAsset,
    math_readout: D04ConditionalTanhReadoutMath,
    readout: AffectiveReadoutCandidate,
    mixed: D04MixedReadoutPreflight,
    scheme_original: D04SchemeOriginalClaimV1,
) -> D04ProductAdmissionCandidateV1:
    """Reject inconsistent premises; return HOLD even when all claims match."""
    if (type(scheme_original) is not D04SchemeOriginalClaimV1
            or scheme_original.status != "claim_requires_w01_durable_original_verification"
            or type(mixed) is not D04MixedReadoutPreflight
            or mixed.status != "unsigned_hold_for_w01_fenced_scc_and_adoption"):
        raise D04ReadoutHold("W01 Scheme original and unsigned mixed premise are required")
    replay = preflight_d04_mixed_readout(
        graph=graph, numeric_snapshot=numeric_snapshot, frame=frame,
        asset=asset, math_readout=math_readout, candidate=readout,
    )
    if replay != mixed:
        raise D04ReadoutHold("mixed readout differs from independent replay")
    fence = frame.source_read.fence
    if (fence is None or fence.graph_revision != graph.graph_revision
            or fence.graph_epoch.revision != graph.query_epoch.revision
            or fence.namespace != graph.namespace):
        raise D04ReadoutHold("W01 current graph fence differs from D04 premise")
    head_version = scheme_original.head_version
    if (type(head_version) is not GraphVersion
            or head_version.key != active_scheme_head_key(graph.namespace)
            or head_version.revision < 1):
        raise D04ReadoutHold("active Scheme head is absent or outside namespace")
    head_atom = frame.source_read.snapshot.get(head_version.key)
    if (head_atom is None or not head_atom.valid
            or head_atom.revision != head_version.revision
            or head_version not in graph.read_versions
            or head_version not in replay.read_versions
            or canonical_digest(head_atom.value) != scheme_original.head_value_digest):
        raise D04ReadoutHold("current Scheme head is missing from full graph fence")
    try:
        value = dict(head_atom.value)
        if value.pop("schema", None) != head_version.key.type_name:
            raise ValueError("Scheme head schema differs")
        head = ActiveSchemeHeadV1(**value)
    except (TypeError, ValueError) as exc:
        raise D04ReadoutHold("active Scheme head original is malformed") from exc
    compiled = scheme_original.compiled_original
    if (type(compiled) is not D12CompiledSchemeV1
            or compiled.namespace != graph.namespace
            or compiled_scheme_digest_v1(compiled) != compiled.compiled_digest
            or head.compiled_digest != compiled.compiled_digest
            or compiled.active_head_ref != head_version.key.token
            or compiled.active_head_revision + 1 != head_version.revision
            or head.draft_ref != compiled.draft_ref
            or head.draft_revision != compiled.draft_revision
            or head.draft_digest != compiled.draft_digest
            or sum(receipt.domain == "d04" for receipt in compiled.domain_receipts) != 1
            or scheme_original.installed_scheme_asset_sha256
               != frame.checkpoint.assets.scheme_sha256
            or scheme_original.scheme_value_digest != canonical_digest(frame.active_scheme)
            or scheme_original.graph_incarnation != frame.graph_incarnation
            or scheme_original.graph_revision != frame.graph_revision
            or math_readout.state_error_2norm < _inherited_radius(frame.checkpoint)):
        raise D04ReadoutHold("Scheme original, installed asset or inherited error differs")
    return D04ProductAdmissionCandidateV1(
        graph.namespace, graph.graph_incarnation, graph.graph_revision,
        graph.query_epoch, graph.access_epoch, graph.delete_epoch,
        replay.graph_version_digest, replay.numeric_inventory_digest,
        replay.source_closure_digest, replay.readout_proof_digest,
        head_version, compiled.compiled_digest,
        scheme_original.installed_scheme_asset_sha256,
        frame.checkpoint.numeric_error_bound, replay.read_versions,
    )


__all__ = ["D04ProductAdmissionCandidateV1", "D04SchemeOriginalClaimV1",
           "compile_d04_product_admission_candidate"]
