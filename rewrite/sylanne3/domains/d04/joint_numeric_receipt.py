"""Canonical D04 joint numeric premise for a future W01 atomic adoption.

This value is deliberately unsigned. W01 must re-read the complete component,
source/access/correction heads and installed Scheme under one Authority fence;
replay the package-bound ABI2 full and leave-family-out solves; and persist the
receipt digest, native identity, source versions and graph/rights epochs in the
same transaction as the joint checkpoint adoption. A product issuer must read
that durable record under a current fence. Constructing this dataclass grants
no authority and cannot set a product-ready state.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import math
import struct

from ...graph_types import AtomKey, GraphVersion
from ...native_runtime.d04_joint_product_math import (
    D04FamilyAssignment, D04JointProductMathCandidate,
)
from ...native_runtime.tanh_interval import _outward_binary64
from ...runtime.joint_numeric_component import JointNumericComponentCandidate
from ...runtime_contracts import NamespaceId, canonical_digest
from .numeric_drive import SourcedNumericDrive
from .numeric_drive import sourced_numeric_drive_write


class D04JointNumericReceiptHold(ValueError):
    """The conditional numeric premise is incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class D04NumericOutputIntervalV1:
    axis_id: str
    output_id: str
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class D04FamilyContributionDoseV1:
    """One family per member, regardless of its number of source rows."""

    family_id: str
    source_refs: tuple[str, ...]
    without_family: tuple[D04NumericOutputIntervalV1, ...]
    contribution_doses: tuple[D04NumericOutputIntervalV1, ...]


@dataclass(frozen=True, slots=True)
class D04JointMemberNumericResultV1:
    checkpoint_ref: str
    full: tuple[D04NumericOutputIntervalV1, ...]
    families: tuple[D04FamilyContributionDoseV1, ...]


@dataclass(frozen=True, slots=True)
class D04JointNumericReceiptCandidateV1:
    namespace: NamespaceId
    component_digest: str
    read_values_digest: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    role_start: float
    role_end: float
    operator_version: str
    native_manifest_sha256: str
    native_sha256: str
    native_abi_version: int
    source_versions: tuple[tuple[str, int, str, int, str, int, str], ...]
    member_refs: tuple[str, ...]
    full_transcript_sha256: str
    family_transcripts: tuple[tuple[str, str], ...]
    math_transcript_sha256: str
    members: tuple[D04JointMemberNumericResultV1, ...]
    receipt_digest: str
    status: str = "unsigned_hold_for_w01_atomic_joint_adoption"

    def __post_init__(self) -> None:
        if self.status != "unsigned_hold_for_w01_atomic_joint_adoption":
            raise ValueError("D04 numeric premise cannot grant trusted adoption")


def _intervals(outputs: tuple) -> tuple[D04NumericOutputIntervalV1, ...]:
    rows = tuple(D04NumericOutputIntervalV1(
        item.axis_id, item.output_id, item.lower, item.upper,
    ) for item in outputs)
    if (len(rows) != 24 or len({row.axis_id for row in rows}) != 24
            or len({row.output_id for row in rows}) != 24
            or any(type(row.lower) is not float or type(row.upper) is not float
                   or not math.isfinite(row.lower) or not math.isfinite(row.upper)
                   or row.lower > row.upper for row in rows)):
        raise D04JointNumericReceiptHold("member result intervals are incomplete")
    return rows


def compile_joint_numeric_receipt_candidate_v1(
    *, component: JointNumericComponentCandidate,
    math_result: D04JointProductMathCandidate,
    drives: tuple[SourcedNumericDrive, ...],
    families: tuple[D04FamilyAssignment, ...],
    operator_version: str,
    native_manifest_sha256: str,
    native_sha256: str,
    native_abi_version: int,
) -> D04JointNumericReceiptCandidateV1:
    """Freeze numeric evidence; only W01 can verify and adopt it durably."""
    if (type(component) is not JointNumericComponentCandidate
            or type(math_result) is not D04JointProductMathCandidate
            or type(drives) is not tuple or type(families) is not tuple
            or component.status != "hold"
            or math_result.status != "conditional_math_hold_for_fenced_graph_and_joint_adoption"
            or math_result.component_digest != component.candidate_digest
            or math_result.member_refs != component.checkpoint_refs
            or tuple(member.checkpoint_ref for member in math_result.members)
               != component.checkpoint_refs
            or len(component.checkpoint_refs) < 2
            or type(operator_version) is not str or not operator_version
            or type(native_abi_version) is not int or native_abi_version != 2
            or any(type(value) is not str or len(value) != 64
                   or any(char not in "0123456789abcdef" for char in value)
                   for value in (native_manifest_sha256, native_sha256,
                                 math_result.full_transcript_sha256,
                                 math_result.transcript_sha256))):
        raise D04JointNumericReceiptHold("joint component, math or ABI2 identity differs")
    assignments = {}
    for item in families:
        if (type(item) is not D04FamilyAssignment
                or type(item.source_ref) is not str or not item.source_ref
                or type(item.family_id) is not str or not item.family_id
                or item.source_ref in assignments):
            raise D04JointNumericReceiptHold("family assignments are ambiguous")
        assignments[item.source_ref] = item.family_id
    if (not assignments or any(type(drive) is not SourcedNumericDrive for drive in drives)
            or set(assignments) != {drive.source_ref for drive in drives}
            or len({drive.drive_id for drive in drives}) != len(drives)):
        raise D04JointNumericReceiptHold("family sources differ from numeric drives")
    family_sources = tuple((family, tuple(sorted(
        source for source, assigned in assignments.items() if assigned == family
    ))) for family in sorted(set(assignments.values())))
    family_ids = tuple(family for family, _ in family_sources)
    if (tuple(family for family, _ in math_result.family_transcripts) != family_ids
            or any(type(digest) is not str or len(digest) != 64
                   or any(char not in "0123456789abcdef" for char in digest)
                   for _, digest in math_result.family_transcripts)):
        raise D04JointNumericReceiptHold("leave-family-out transcripts differ")
    expected_drives = {
        version.key.token: (version.revision, block.checkpoint_ref,
                            block.checkpoint_version.revision,
                            component.role_start, component.role_end, values)
        for block in component.block_drives
        for version, values in zip(block.drive_versions, block.drives)
    }
    source_versions = tuple(sorted((
        sourced_numeric_drive_write(drive).key.token, drive.drive_version,
        drive.source_ref, drive.source_revision,
        drive.access_ref, drive.access_revision,
        assignments[drive.source_ref],
    ) for drive in drives))
    if (len(source_versions) != len(drives)
            or len(expected_drives) != len(drives)
            or {row[0]: row[1] for row in source_versions}
               != {token: values[0] for token, values in expected_drives.items()}
            or len({row[0] for row in source_versions}) != len(drives)):
        raise D04JointNumericReceiptHold("drive revisions differ from component")
    for drive in drives:
        expected = expected_drives[sourced_numeric_drive_write(drive).key.token]
        if (drive.checkpoint_ref != expected[1]
                or drive.checkpoint_revision != expected[2]
                or (drive.role_start, drive.role_end) != expected[3:5]
                or GraphVersion(AtomKey.from_token(drive.source_ref),
                                drive.source_revision) not in component.read_versions
                or GraphVersion(AtomKey.from_token(drive.access_ref),
                                drive.access_revision) not in component.read_versions
                or tuple(struct.pack("!d", value) for value in drive.drive)
                   != tuple(struct.pack("!d", value) for value in expected[5])):
            raise D04JointNumericReceiptHold("drive values differ from frozen component")
    members = []
    for member in math_result.members:
        full = _intervals(member.full.outputs)
        if (tuple(family for family, _ in member.without_family) != family_ids
                or tuple(family for family, _ in member.effects) != family_ids):
            raise D04JointNumericReceiptHold("member family branches are incomplete")
        doses = []
        for (family, without), (_, effects), (_, sources) in zip(
                member.without_family, member.effects, family_sources):
            absent = _intervals(without.outputs)
            if (tuple((row.axis_id, row.output_id) for row in absent)
                    != tuple((row.axis_id, row.output_id) for row in full)
                    or len(effects) != len(full)):
                raise D04JointNumericReceiptHold("member branch output axes differ")
            intervals = []
            for whole, omitted, effect in zip(full, absent, effects):
                lower = _outward_binary64(
                    Fraction.from_float(whole.lower) - Fraction.from_float(omitted.upper),
                    lower=True,
                )
                upper = _outward_binary64(
                    Fraction.from_float(whole.upper) - Fraction.from_float(omitted.lower),
                    lower=False,
                )
                if effect != (lower, upper):
                    raise D04JointNumericReceiptHold("family contribution dose differs")
                intervals.append(D04NumericOutputIntervalV1(
                    whole.axis_id, whole.output_id, lower, upper,
                ))
            doses.append(D04FamilyContributionDoseV1(
                family, sources, absent, tuple(intervals),
            ))
        members.append(D04JointMemberNumericResultV1(member.checkpoint_ref, full, tuple(doses)))
    fields = dict(
        namespace=component.namespace, component_digest=component.candidate_digest,
        read_values_digest=component.read_values_digest,
        graph_incarnation=component.graph_incarnation,
        graph_revision=component.graph_revision,
        graph_epoch=component.query_epoch.revision,
        access_epoch=component.access_epoch, delete_epoch=component.delete_epoch,
        role_start=component.role_start, role_end=component.role_end,
        operator_version=operator_version,
        native_manifest_sha256=native_manifest_sha256, native_sha256=native_sha256,
        native_abi_version=native_abi_version,
        source_versions=source_versions, member_refs=component.checkpoint_refs,
        full_transcript_sha256=math_result.full_transcript_sha256,
        family_transcripts=math_result.family_transcripts,
        math_transcript_sha256=math_result.transcript_sha256,
        members=tuple(members),
    )
    return D04JointNumericReceiptCandidateV1(
        **fields, receipt_digest=canonical_digest(fields),
    )


def verify_joint_numeric_receipt_candidate_v1(
    receipt: D04JointNumericReceiptCandidateV1, *,
    component: JointNumericComponentCandidate,
    math_result: D04JointProductMathCandidate,
    drives: tuple[SourcedNumericDrive, ...],
    families: tuple[D04FamilyAssignment, ...],
    operator_version: str,
    native_manifest_sha256: str,
    native_sha256: str,
    native_abi_version: int,
) -> bool:
    """Pure equality/replay check; does not authenticate caller inputs or graph."""
    if type(receipt) is not D04JointNumericReceiptCandidateV1:
        return False
    try:
        expected = compile_joint_numeric_receipt_candidate_v1(
            component=component, math_result=math_result, drives=drives,
            families=families, operator_version=operator_version,
            native_manifest_sha256=native_manifest_sha256,
            native_sha256=native_sha256, native_abi_version=native_abi_version,
        )
    except (TypeError, ValueError):
        return False
    return receipt == expected


__all__ = [
    "D04JointNumericReceiptHold", "D04NumericOutputIntervalV1",
    "D04FamilyContributionDoseV1", "D04JointMemberNumericResultV1",
    "D04JointNumericReceiptCandidateV1",
    "compile_joint_numeric_receipt_candidate_v1",
    "verify_joint_numeric_receipt_candidate_v1",
]
