"""D04 current product readout issuer for a trusted W01 coordinator read port.

The installed issuer accepts no caller-supplied graph snapshot, Scheme, asset,
or ABI2 certificate. W01 must produce and validate the read frame inside its
current Authority read fence. Until that port and a formal package exist,
construction and issuance fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import math
from pathlib import Path
import secrets
from typing import Callable, Protocol, TypeVar

from ...native_runtime.d04_tanh_readout_asset import (
    ASSET_NAME, load_d04_tanh_readout_asset,
)
from ...native_runtime.loader import load_production_native
from ...native_runtime.tanh_asset_readout import run_d04_conditional_tanh_readout_math
from ...runtime_contracts import AuthorityContext, NamespaceId, canonical_digest, canonical_serialize
from .affect import AffectScheme
from .product_readout import (
    AffectiveReadoutCandidate, D04ReadoutHold, _inherited_radius,
    project_conditional_affect_behaviour,
)
from .root import NumericCheckpoint
from .source_head import D04SourceHeadRead


_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class D04VerifiedNumericAdoptionV1:
    """W01's result of checking a persisted adoption and its ABI2 certificate.

    This DTO is not itself an authority credential. Only a frame returned by
    the installed coordinator callback may be used by this issuer.
    """

    checkpoint_ref: str
    checkpoint_revision: int
    commit_operation_id: str
    commit_receipt_digest: str
    certificate_source: str
    certificate_digest: str
    asset_digest: str
    numeric_error_bound: float
    native_manifest_sha256: str
    native_sha256: str
    graph_closure_digest: str
    status: str = "coordinator_verified_adoption"


@dataclass(frozen=True, slots=True)
class D04CurrentProductReadFrameV1:
    """One complete, current graph read supplied only inside W01's read fence."""

    checkpoint: NumericCheckpoint
    checkpoint_ref: str
    checkpoint_revision: int
    source_ref: str
    source_read: D04SourceHeadRead
    active_scheme: AffectScheme
    adoption: D04VerifiedNumericAdoptionV1
    graph_incarnation: str
    graph_revision: int
    access_epoch: int
    delete_epoch: int


class D04CurrentProductReadPort(Protocol):
    def with_current_d04_product_readout_v1(
        self, authority: AuthorityContext, lease: object, *, checkpoint_ref: str,
        audience: tuple[str, ...], purpose: str,
        project: Callable[[D04CurrentProductReadFrameV1], _T],
    ) -> _T: ...


@dataclass(frozen=True, slots=True)
class D04ProductReadoutReceiptV1:
    """Current at issuance; downstream must call issuer.verify_current again."""

    namespace: NamespaceId
    audience: tuple[str, ...]
    purpose: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    adoption_receipt_digest: str
    readout: AffectiveReadoutCandidate
    issuer_seal: str
    status: str = "d04_readout_issued_at_current_fence"


class D04ProductReadoutIssuer:
    """Installed, private issuer; receipt possession confers no action permission."""

    def __init__(
        self, *, read_port: D04CurrentProductReadPort,
        package_root: Path,
        expected_manifest_sha256: str, expected_readout_id: str,
        available_cpu_features: frozenset[str] | None = None,
    ) -> None:
        if not callable(getattr(read_port, "with_current_d04_product_readout_v1", None)):
            raise D04ReadoutHold("W01 current D04 product read port is unavailable")
        if (not isinstance(package_root, Path) or not package_root.is_absolute()
                or not expected_readout_id):
            raise D04ReadoutHold("trusted installed package and readout identity are required")
        from ...host.affect_scheme_asset import load_verified_affect_scheme

        try:
            handle = load_production_native(
                package_root, trusted_manifest_sha256=expected_manifest_sha256,
            )
            verified = load_verified_affect_scheme(
                package_root, expected_manifest_sha256,
                available_cpu_features=available_cpu_features,
            )
        except (TypeError, ValueError, RuntimeError, OSError) as exc:
            raise D04ReadoutHold("formal ABI2 package and active D04 Scheme are unavailable") from exc
        if (handle.production_binding is None
                or handle.production_binding.abi_version != 2
                or not handle.capabilities.supports_fixed_block_interval_math_v1):
            raise D04ReadoutHold("package-bound ABI2 numerical verifier is unavailable")
        binding = handle.production_binding
        if binding.manifest_sha256 != verified.manifest_sha256:
            raise D04ReadoutHold("ABI2 library and active Scheme belong to different packages")
        self._read_port = read_port
        self._handle = handle
        self._root = package_root
        self._scheme = verified.scheme
        self._scheme_sha256 = verified.asset_sha256
        self._readout_id = expected_readout_id
        self._seal_key = secrets.token_bytes(32)

    def _asset(self, checkpoint: NumericCheckpoint):
        """Recheck the installed manifest entry and checkpoint-pinned asset."""
        from ...host.affect_scheme_asset import _listed_bytes, _json_object
        from ...native_runtime.d04_candidate import _assets

        binding = self._handle.production_binding
        assert binding is not None
        try:
            affect, scheme_hash, operator, operator_hash = _assets(self._root, self._handle)
            if (scheme_hash != self._scheme_sha256
                    or scheme_hash != checkpoint.assets.scheme_sha256
                    or operator_hash != checkpoint.assets.operator_sha256
                    or any(affect.get(name) != getattr(self._scheme, name)
                           or operator.get(name) != getattr(self._scheme, name)
                           for name in ("scheme_version", "operator_version",
                                        "parameter_version", "coupling_version"))
                    or affect.get("axes") != [
                        {"axis_id": axis.axis_id, "unit": axis.unit, "meaning": axis.meaning}
                        for axis in self._scheme.axes
                    ]):
                raise ValueError("installed D04 Scheme or operator differs")
            manifest_bytes = (self._root / "release-manifest.json").read_bytes()
            if hashlib.sha256(manifest_bytes).hexdigest() != binding.manifest_sha256:
                raise ValueError("installed release manifest changed")
            manifest = _json_object(manifest_bytes, "release manifest")
            raw, entry = _listed_bytes(
                self._root, manifest, "resources/catalogue/" + ASSET_NAME,
            )
            if (entry["sha256"] != checkpoint.assets.readout_sha256
                    or hashlib.sha256(raw).hexdigest() != entry["sha256"]):
                raise ValueError("installed D04 readout differs from checkpoint")
            return load_d04_tanh_readout_asset(
                self._root / "resources" / "catalogue", checkpoint.assets,
                expected_readout_id=self._readout_id,
            )
        except (TypeError, ValueError, OSError, KeyError) as exc:
            raise D04ReadoutHold("installed D04 readout asset is unavailable") from exc

    @staticmethod
    def _closure_digest(read: D04SourceHeadRead) -> str:
        if not read.snapshot.atoms or len(read.snapshot.atoms) > 1024:
            raise D04ReadoutHold("complete D04 graph closure is unavailable")
        return canonical_digest(tuple(sorted(
            (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
            for atom in read.snapshot.atoms
        )))

    def _project(self, frame: D04CurrentProductReadFrameV1, authority: AuthorityContext,
                 checkpoint_ref: str, audience: tuple[str, ...], purpose: str,
                 ) -> D04ProductReadoutReceiptV1:
        if type(frame) is not D04CurrentProductReadFrameV1:
            raise D04ReadoutHold("W01 did not return a typed current D04 read")
        checkpoint, read, adoption = frame.checkpoint, frame.source_read, frame.adoption
        binding = self._handle.production_binding
        if (type(checkpoint) is not NumericCheckpoint
                or type(read) is not D04SourceHeadRead
                or type(adoption) is not D04VerifiedNumericAdoptionV1
                or type(frame.active_scheme) is not AffectScheme
                or frame.active_scheme != self._scheme
                or binding is None or read.namespace != authority.namespace
                or read.audience != audience or read.purpose != purpose
                or read.fence is None
                or read.fence.generation != authority.activation_generation
                or read.fence.graph_revision != frame.graph_revision
                or read.snapshot.epochs != (read.fence.graph_epoch,)
                or frame.checkpoint_ref != checkpoint_ref
                or checkpoint.namespace != authority.namespace.as_tuple
                or adoption.status != "coordinator_verified_adoption"
                or adoption.checkpoint_ref != frame.checkpoint_ref
                or adoption.checkpoint_revision != frame.checkpoint_revision
                or adoption.commit_operation_id != checkpoint.commit_operation_id
                or adoption.certificate_source != checkpoint.certificate_source
                or adoption.certificate_digest != checkpoint.certificate_digest
                or adoption.asset_digest != checkpoint.asset_digest
                or adoption.numeric_error_bound != checkpoint.numeric_error_bound
                or adoption.native_manifest_sha256 != binding.manifest_sha256
                or adoption.native_sha256 != binding.native_sha256
                or adoption.graph_closure_digest != self._closure_digest(read)
                or type(frame.access_epoch) is not int or frame.access_epoch < 0
                or type(frame.delete_epoch) is not int or frame.delete_epoch < 0
                or type(frame.graph_revision) is not int or frame.graph_revision < 0
                or type(frame.graph_incarnation) is not str or not frame.graph_incarnation):
            raise D04ReadoutHold("current graph, Scheme or verified ABI2 adoption differs")
        asset = self._asset(checkpoint)
        math_readout = run_d04_conditional_tanh_readout_math(
            asset, checkpoint.latent_state, _inherited_radius(checkpoint),
        )
        candidate = project_conditional_affect_behaviour(
            checkpoint=checkpoint, checkpoint_ref=frame.checkpoint_ref,
            checkpoint_revision=frame.checkpoint_revision,
            source_ref=frame.source_ref, source_read=read,
            scheme=frame.active_scheme, asset=asset, math_readout=math_readout,
        )
        if not adoption.commit_receipt_digest or not all(math.isfinite(item)
               for item in (checkpoint.cursor, checkpoint.numeric_error_bound)):
            raise D04ReadoutHold("verified numeric adoption receipt is incomplete")
        receipt = D04ProductReadoutReceiptV1(
            authority.namespace, audience, purpose,
            frame.graph_incarnation, frame.graph_revision,
            read.snapshot.epochs[0].revision, frame.access_epoch, frame.delete_epoch,
            adoption.commit_receipt_digest, candidate, "",
        )
        seal = hmac.new(self._seal_key, canonical_serialize(replace(
            receipt, issuer_seal="",
        )).encode("utf-8"), hashlib.sha256).hexdigest()
        return replace(receipt, issuer_seal=seal)

    def issue_current(self, authority: AuthorityContext, lease: object, *,
                      checkpoint_ref: str, audience: tuple[str, ...],
                      purpose: str) -> D04ProductReadoutReceiptV1:
        if (type(authority) is not AuthorityContext
                or "persona" not in authority.owner_scope
                or type(audience) is not tuple
                or not audience or any(type(item) is not str or not item
                                    for item in audience)
                or not set(audience).issubset(authority.audience)
                or purpose != authority.purpose):
            raise D04ReadoutHold("D04 readout Authority scope differs")
        return self._read_port.with_current_d04_product_readout_v1(
            authority, lease, checkpoint_ref=checkpoint_ref,
            audience=audience, purpose=purpose,
            project=lambda frame: self._project(
                frame, authority, checkpoint_ref, audience, purpose,
            ),
        )

    def verify_current(self, receipt: D04ProductReadoutReceiptV1,
                       authority: AuthorityContext, lease: object) -> bool:
        if (type(receipt) is not D04ProductReadoutReceiptV1
                or type(receipt.issuer_seal) is not str):
            return False
        try:
            expected = hmac.new(self._seal_key, canonical_serialize(replace(
                receipt, issuer_seal="",
            )).encode("utf-8"), hashlib.sha256).hexdigest()
        except (TypeError, ValueError, AttributeError):
            return False
        if not hmac.compare_digest(receipt.issuer_seal, expected):
            return False
        try:
            current = self.issue_current(
                authority, lease, checkpoint_ref=receipt.readout.checkpoint_ref,
                audience=receipt.audience, purpose=receipt.purpose,
            )
        except (D04ReadoutHold, ValueError, PermissionError):
            return False
        return hmac.compare_digest(current.issuer_seal, receipt.issuer_seal)


__all__ = ["D04CurrentProductReadFrameV1", "D04CurrentProductReadPort",
           "D04ProductReadoutIssuer", "D04ProductReadoutReceiptV1",
           "D04VerifiedNumericAdoptionV1"]
