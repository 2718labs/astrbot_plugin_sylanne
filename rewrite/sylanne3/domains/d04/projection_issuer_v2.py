"""Installed D04 encoding projection issuer, awaiting W01's durable joint port.

The caller supplies only an Authority/Owner lease and baseline/source identity.
The installed W01 callback must authenticate its live fence, source closure and
durable joint numeric original. This module emits unsigned CAS inputs only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
from pathlib import Path
from typing import Callable, Protocol, TypeVar

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...host.affect_scheme_asset import _json_object, _listed_bytes
from ...host.installed_package import verify_installed_backend_runtime_v1
from ...native_runtime.d04_tanh_readout_asset import (
    ASSET_NAME, D04LoadedTanhReadoutAsset, load_d04_tanh_readout_asset,
)
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import AuthorityContext, FenceScope, NamespaceId, canonical_digest
from ..d06 import source_correction_head_key
from .encoding_baseline_v2 import (
    EncodingBaselineCandidateV2, EncodingProjectionReceiptCandidateV2,
    ExactGraphRefV2, ProjectionMemberV2, ProjectionNumericErrorV2,
    encoding_input_binding_digest_v2,
)
from .interval_projection_v2 import (
    D04IntervalProjectionCandidateV2, D04IntervalProjectionPolicyV2,
    D04ProjectionMemberBindingV2, project_joint_interval_candidate_v2,
)
from .joint_numeric_receipt import D04JointNumericReceiptCandidateV1
from .root import RootAssetBindings
from .numeric_coupling import SCHEME_VERSION


_T = TypeVar("_T")
_POLICY_PATH = "resources/catalogue/d04-interval-projection-policy.v2.json"
_READOUT_PATH = "resources/catalogue/" + ASSET_NAME


class D04ProjectionIssuerHold(ValueError):
    """An installed/current projection prerequisite is absent or mismatched."""


@dataclass(frozen=True, slots=True)
class D04VerifiedJointProjectionOriginalV2:
    """W01-only view of a durable adopted original; this DTO grants no trust."""

    original_ref: str
    original_revision: int
    receipt: D04JointNumericReceiptCandidateV1
    adoption_operation_id: str
    adoption_receipt_digest: str
    numeric_error: ProjectionNumericErrorV2
    status: str = "w01_verified_durable_joint_original_v2"


@dataclass(frozen=True, slots=True)
class D04CurrentProjectionReadFrameV2:
    """Constructed only within W01's current Owner-fenced reader callback."""

    namespace: NamespaceId
    baseline_id: str
    source_ref: str
    source_versions: tuple[ExactGraphRefV2, ...]
    source_access_correction_versions: tuple[GraphVersion, ...]
    perspective_version: ExactGraphRefV2
    interpretation_versions: tuple[ExactGraphRefV2, ...]
    then_feeling_versions: tuple[ExactGraphRefV2, ...]
    member_bindings: tuple[D04ProjectionMemberBindingV2, ...]
    as_known_at: float
    snapshot: GraphSnapshot
    fence: FenceScope
    joint_original: D04VerifiedJointProjectionOriginalV2
    graph_incarnation: str
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    status: str = "w01_current_fenced_joint_projection_read_v2"


class D04CurrentProjectionReadPortV2(Protocol):
    def with_current_d04_encoding_projection_v2(
        self, authority: AuthorityContext, lease: object, *, baseline_id: str,
        source_ref: str, audience: tuple[str, ...], purpose: str,
        project: Callable[[D04CurrentProjectionReadFrameV2], _T],
    ) -> _T: ...


@dataclass(frozen=True, slots=True)
class D04EncodingProjectionProposalV2:
    """Unsigned proposal; W01 must recheck and atomically adopt or reject it."""

    baseline: EncodingBaselineCandidateV2
    projection: D04IntervalProjectionCandidateV2
    source_ref: str
    original_ref: str
    original_revision: int
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    status: str = "unsigned_hold_for_w01_atomic_baseline_cas"


def load_installed_d04_projection_assets_v2(
    package_root: Path, expected_manifest_sha256: str,
    available_cpu_features: frozenset[str] | None = None,
) -> tuple[D04IntervalProjectionPolicyV2, D04LoadedTanhReadoutAsset]:
    """Authenticate the exact policy and readout bytes pinned by a formal install."""
    verification = verify_installed_backend_runtime_v1(
        package_root, expected_manifest_sha256,
        available_cpu_features=available_cpu_features,
    )
    if not verification.verified:
        raise D04ProjectionIssuerHold("verified formal D04 package is unavailable")
    try:
        raw_manifest = (package_root / "release-manifest.json").read_bytes()
        if not hmac.compare_digest(hashlib.sha256(raw_manifest).hexdigest(),
                                   expected_manifest_sha256):
            raise ValueError("manifest changed")
        manifest = _json_object(raw_manifest, "release manifest")
        binding = manifest.get("interval_projection_policy")
        if (type(binding) is not dict
                or set(binding) != {"path", "sha256", "bytes", "policy_id",
                                    "version", "stage_contract",
                                    "semantic_calibration", "status"}
                or binding.get("path") != _POLICY_PATH
                or binding.get("stage_contract") !=
                "encoding_baseline_then_recollection_current_mood"
                or binding.get("semantic_calibration") != "unvalidated"
                or binding.get("status") != (
                    "installed" if verification.build_mode == "formal-alpha1" else "candidate")):
            raise ValueError("projection policy manifest binding differs")
        policy_raw, policy_entry = _listed_bytes(package_root, manifest, _POLICY_PATH)
        readout_raw, readout_entry = _listed_bytes(package_root, manifest, _READOUT_PATH)
        if (any(binding.get(name) != policy_entry.get(name)
                for name in ("path", "sha256", "bytes"))
                or len(policy_raw) > 64 * 1024 or len(readout_raw) > 64 * 1024):
            raise ValueError("projection policy is not exactly manifest-pinned")
        data = _json_object(policy_raw, "D04 interval projection policy")
        if set(data) != set(D04IntervalProjectionPolicyV2.__dataclass_fields__):
            raise ValueError("projection policy fields differ")
        policy = D04IntervalProjectionPolicyV2(**data)
        if (binding.get("policy_id") != policy.policy_id
                or binding.get("version") != policy.version
                or policy.readout_sha256 != readout_entry["sha256"]):
            raise ValueError("policy and readout manifest identities differ")
        # The public asset parser only uses readout and scheme fields here.
        unused_hash = "0" * 64
        bindings = RootAssetBindings(
            SCHEME_VERSION, "unverified", "unverified", "unverified",
            policy.readout_version, unused_hash, unused_hash, unused_hash,
            unused_hash, policy.readout_sha256,
        )
        asset = load_d04_tanh_readout_asset(
            package_root / "resources" / "catalogue", bindings,
            expected_readout_id=policy.readout_id,
        )
        if asset.asset_sha256 != hashlib.sha256(readout_raw).hexdigest():
            raise ValueError("installed readout bytes changed")
        return policy, asset
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise D04ProjectionIssuerHold("installed projection policy/readout unavailable") from exc


class D04InstalledProjectionIssuerV2:
    """Only an administrator-pinned formal package and installed W01 port qualify."""

    def __init__(
        self, *, read_port: D04CurrentProjectionReadPortV2, package_root: Path,
        expected_manifest_sha256: str,
        available_cpu_features: frozenset[str] | None = None,
    ) -> None:
        if not callable(getattr(read_port, "with_current_d04_encoding_projection_v2", None)):
            raise D04ProjectionIssuerHold("W01 current D04 projection reader is unavailable")
        if (not isinstance(package_root, Path) or not package_root.is_absolute()
                or type(expected_manifest_sha256) is not str
                or len(expected_manifest_sha256) != 64):
            raise D04ProjectionIssuerHold("administrator-pinned package identity is required")
        self._read_port = read_port
        self._root = package_root
        self._manifest_sha256 = expected_manifest_sha256
        self._features = available_cpu_features
        self._policy, self._asset = self._installed_assets()

    def _installed_assets(self) -> tuple[D04IntervalProjectionPolicyV2,
                                          D04LoadedTanhReadoutAsset]:
        return load_installed_d04_projection_assets_v2(
            self._root, self._manifest_sha256, self._features,
        )

    @staticmethod
    def _check_source_closure(
        frame: D04CurrentProjectionReadFrameV2,
        receipt: D04JointNumericReceiptCandidateV1,
        audience: tuple[str, ...], purpose: str,
    ) -> None:
        """Check exact source, access and correction rows supplied by W01."""
        versions = frame.source_access_correction_versions
        if (type(versions) is not tuple
                or len(set(versions)) != len(versions)
                or any(type(item) is not GraphVersion for item in versions)):
            raise D04ProjectionIssuerHold("W01 source rights versions are incomplete")
        version_set = set(versions)
        source_ids = {item.key.owner.subject for item in frame.source_versions}
        source_refs = {item.ref: item.revision for item in frame.source_versions}
        for source in frame.source_versions:
            key = source.key
            source_id = key.owner.subject
            if (source_id is None or key != source_key(*frame.namespace.as_tuple,
                                                       source_id)):
                raise D04ProjectionIssuerHold("source namespace differs")
            source_atom = frame.snapshot.get(key)
            access = access_key(*frame.namespace.as_tuple, source_id)
            correction = source_correction_head_key(frame.namespace, source_id)
            access_atom = frame.snapshot.get(access)
            correction_atom = frame.snapshot.get(correction)
            if (source_atom is None or not source_atom.valid
                    or source_atom.revision != source.revision
                    or access_atom is None or not access_atom.valid
                    or correction_atom is None or correction_atom.valid
                    or GraphVersion(access, access_atom.revision) not in version_set
                    or GraphVersion(correction, correction_atom.revision) not in version_set):
                raise D04ProjectionIssuerHold("source/access/correction version differs")
            try:
                record = SourceRecord.from_dict(source_atom.value)
                validate_access(access_atom.value)
            except (TypeError, ValueError) as exc:
                raise D04ProjectionIssuerHold("source access record is invalid") from exc
            if (record.source_id != source_id
                    or access_atom.value["source_id"] != source_id
                    or access_atom.value["status"] != "active"
                    or purpose not in record.purposes
                    or purpose not in access_atom.value["purposes"]
                    or not set(audience).issubset(record.audiences)
                    or not set(audience).issubset(access_atom.value["audiences"])
                    or not set(record.parent_source_ids).issubset(source_ids)):
                raise D04ProjectionIssuerHold("source access or ancestry differs")
        if len(versions) != 2 * len(frame.source_versions):
            raise D04ProjectionIssuerHold("numeric drive and current rights versions differ")
        for row in receipt.source_versions:
            if (type(row) is not tuple or len(row) != 7
                    or row[2] not in source_refs or row[3] != source_refs[row[2]]):
                raise D04ProjectionIssuerHold("numeric drive source version differs")
            try:
                source_key_value = AtomKey.from_token(row[2])
                access_key_value = AtomKey.from_token(row[4])
                if (access_key_value != access_key(*frame.namespace.as_tuple,
                                                   source_key_value.owner.subject or "")
                        or GraphVersion(access_key_value, row[5]) not in version_set):
                    raise ValueError("access version differs")
            except (TypeError, ValueError) as exc:
                raise D04ProjectionIssuerHold("numeric drive access version differs") from exc

    def _project(
        self, frame: D04CurrentProjectionReadFrameV2, authority: AuthorityContext,
        baseline_id: str, source_ref: str, audience: tuple[str, ...], purpose: str,
    ) -> D04EncodingProjectionProposalV2:
        if type(frame) is not D04CurrentProjectionReadFrameV2:
            raise D04ProjectionIssuerHold("W01 returned no typed current projection read")
        original = frame.joint_original
        if type(original) is not D04VerifiedJointProjectionOriginalV2:
            raise D04ProjectionIssuerHold("W01 durable joint original is unavailable")
        receipt = original.receipt
        if (frame.status != "w01_current_fenced_joint_projection_read_v2"
                or original.status != "w01_verified_durable_joint_original_v2"
                or type(receipt) is not D04JointNumericReceiptCandidateV1
                or type(frame.snapshot) is not GraphSnapshot
                or type(frame.fence) is not FenceScope
                or frame.fence.operation != "read"
                or frame.fence.namespace != authority.namespace
                or frame.fence.generation != authority.activation_generation
                or frame.fence.graph_revision != frame.graph_revision
                or frame.snapshot.epochs != (frame.fence.graph_epoch,)
                or frame.namespace != authority.namespace
                or frame.baseline_id != baseline_id or frame.source_ref != source_ref
                or receipt.namespace != frame.namespace
                or receipt.graph_incarnation != frame.graph_incarnation
                # The adopted numeric receipt records the prewrite snapshot.
                # Only the outer proposal carries the current CAS stamp.
                or receipt.graph_revision > frame.graph_revision
                or receipt.graph_epoch > frame.fence.graph_epoch.revision
                or receipt.access_epoch > frame.access_epoch
                or receipt.delete_epoch > frame.delete_epoch
                or receipt.native_manifest_sha256 != self._manifest_sha256
                or receipt.native_abi_version != 2
                or type(original.numeric_error) is not ProjectionNumericErrorV2
                or not original.adoption_operation_id
                or not original.adoption_receipt_digest
                or type(original.original_revision) is not int
                or original.original_revision < 1):
            raise D04ProjectionIssuerHold("current joint original or graph identity differs")
        if (tuple(binding.checkpoint_ref for binding in frame.member_bindings)
                != receipt.member_refs
                or tuple(item.ref for item in frame.then_feeling_versions)
                != tuple(binding.feeling_ref for binding in frame.member_bindings)
                or tuple(item.revision for item in frame.then_feeling_versions)
                != tuple(binding.feeling_revision for binding in frame.member_bindings)
                or source_ref not in {item.ref for item in frame.source_versions}):
            raise D04ProjectionIssuerHold("complete member or source identity differs")
        if (type(frame.source_versions) is not tuple
                or type(frame.interpretation_versions) is not tuple
                or type(frame.then_feeling_versions) is not tuple
                or any(type(item) is not ExactGraphRefV2 for item in (
                    *frame.source_versions, frame.perspective_version,
                    *frame.interpretation_versions, *frame.then_feeling_versions,
                ))):
            raise D04ProjectionIssuerHold("W01 exact source/interpretation versions absent")
        self._check_source_closure(frame, receipt, audience, purpose)
        try:
            proposal = project_joint_interval_candidate_v2(
                receipt=receipt, asset=self._asset, policy=self._policy,
                member_bindings=frame.member_bindings,
                then_feeling_versions=tuple(GraphVersion(item.key, item.revision)
                                            for item in frame.then_feeling_versions),
            )
            members = tuple(ProjectionMemberV2(
                feeling, binding.checkpoint_ref, binding.checkpoint_revision,
            ) for feeling, binding in zip(frame.then_feeling_versions,
                                          frame.member_bindings))
            projection_receipt = EncodingProjectionReceiptCandidateV2(
                input_binding_digest=encoding_input_binding_digest_v2(
                    baseline_id, frame.source_versions, frame.perspective_version,
                    frame.interpretation_versions, frame.then_feeling_versions,
                    frame.as_known_at,
                ),
                members=members, component_digest=receipt.component_digest,
                joint_numeric_receipt_digest=receipt.receipt_digest,
                joint_adoption_operation_id=original.adoption_operation_id,
                joint_adoption_receipt_digest=original.adoption_receipt_digest,
                projection_policy_ref=self._policy.policy_id,
                projection_policy_version=self._policy.version,
                policy_digest=canonical_digest(asdict(self._policy)),
                readout_asset_id=self._asset.readout_id,
                readout_asset_version=self._asset.readout_version,
                readout_asset_sha256=self._asset.asset_sha256,
                native_manifest_sha256=receipt.native_manifest_sha256,
                native_sha256=receipt.native_sha256,
                native_abi_version=receipt.native_abi_version,
                full_transcript_sha256=receipt.full_transcript_sha256,
                projection_proof_digest=proposal.proof_digest,
                mood_receipt_digest=None,
                graph_incarnation=receipt.graph_incarnation,
                graph_revision=receipt.graph_revision,
                graph_epoch=receipt.graph_epoch,
                access_epoch=receipt.access_epoch,
                delete_epoch=receipt.delete_epoch,
                role_start=receipt.role_start, role_end=receipt.role_end,
                salience_interval=proposal.salience_interval,
                tone_interval=proposal.tone_interval,
                numeric_error=original.numeric_error,
            )
            baseline = EncodingBaselineCandidateV2(
                baseline_id, frame.source_versions, frame.perspective_version,
                frame.interpretation_versions, frame.then_feeling_versions,
                frame.as_known_at, projection_receipt,
            )
            baseline.verify_refs_in_snapshot(frame.snapshot)
            projection_receipt.verify_projection_candidate(proposal)
        except (TypeError, ValueError, AttributeError) as exc:
            raise D04ProjectionIssuerHold("current projection premise differs") from exc
        return D04EncodingProjectionProposalV2(
            baseline, proposal, source_ref, original.original_ref,
            original.original_revision,
            frame.graph_incarnation, frame.graph_revision,
            frame.fence.graph_epoch.revision, frame.access_epoch, frame.delete_epoch,
        )

    def issue_current(
        self, authority: AuthorityContext, lease: object, *, baseline_id: str,
        source_ref: str, audience: tuple[str, ...], purpose: str,
    ) -> D04EncodingProjectionProposalV2:
        if (type(authority) is not AuthorityContext
                or "persona" not in authority.owner_scope
                or type(baseline_id) is not str or not baseline_id
                or type(source_ref) is not str or not source_ref
                or type(audience) is not tuple or not audience
                or any(type(item) is not str or not item or item == "*"
                       for item in audience)
                or not set(audience).issubset(authority.audience)
                or purpose != authority.purpose):
            raise D04ProjectionIssuerHold("projection Authority or identity scope differs")
        # Installed W01 port owns the lease check and keeps the callback in its
        # live read transaction. No caller-controlled snapshot reaches here.
        return self._read_port.with_current_d04_encoding_projection_v2(
            authority, lease, baseline_id=baseline_id, source_ref=source_ref,
            audience=audience, purpose=purpose,
            project=lambda frame: self._project(frame, authority, baseline_id,
                                                source_ref, audience, purpose),
        )

    def verify_current(
        self, proposal: D04EncodingProjectionProposalV2,
        authority: AuthorityContext, lease: object, *, audience: tuple[str, ...],
        purpose: str,
    ) -> bool:
        """Consumer-side re-read; W01 still must perform atomic version-0 CAS."""
        if type(proposal) is not D04EncodingProjectionProposalV2:
            return False
        try:
            current = self.issue_current(
                authority, lease, baseline_id=proposal.baseline.baseline_id,
                source_ref=proposal.source_ref,
                audience=audience, purpose=purpose,
            )
        except (D04ProjectionIssuerHold, ValueError, PermissionError, IndexError):
            return False
        return current == proposal


__all__ = [
    "D04ProjectionIssuerHold", "D04VerifiedJointProjectionOriginalV2",
    "D04CurrentProjectionReadFrameV2", "D04CurrentProjectionReadPortV2",
    "D04EncodingProjectionProposalV2", "D04InstalledProjectionIssuerV2",
    "load_installed_d04_projection_assets_v2",
]
