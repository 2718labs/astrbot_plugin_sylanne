"""Conditional, graph-bound D04 interval dose and continuous-rate contract.

The unit of allocation is one D06 provenance family over *all* D04 blocks.
This pure compiler has no Authority fence or authenticated semantic mapping
receipt, so its result is always held for W01 adoption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d01 import ActiveRoleQualification
from ..d06 import source_correction_head_key
from .affect import _decode_appraisal
from .drive_allocation import CompiledDrivePolicy, RoleCondition
from .numeric_coupling import REGISTERED_AXIS_IDS


SCHEMA = "d04.family_interval_drive_candidate.v2"
SHARED_SCHEMA = "d04.family_interval_drive_candidate.v3"
_REALITY = {
    "observed": ("observed", "external_observation"),
    "reported": ("reported", "external_report"),
    "authored": ("authored", "authored_content"),
    "internal": ("derived", "inference"),
    "simulated": ("simulated", "simulation"),
}


class FamilyDriveHold(ValueError):
    """The supplied graph or allocation cannot support a family candidate."""


@dataclass(frozen=True, slots=True)
class AffineTimeMapV1:
    role_start: float
    role_end: float
    solver_start: float
    solver_end: float
    schema: str = "d04.affine_role_to_solver_time.v1"
    mapping_ref: str = "d04.role_solver_identity.v1"

    def __post_init__(self) -> None:
        if (self.schema != "d04.affine_role_to_solver_time.v1"
                or type(self.mapping_ref) is not str or not self.mapping_ref
                or any(type(x) not in (int, float) or not math.isfinite(x)
                       for x in (self.role_start, self.role_end,
                                 self.solver_start, self.solver_end))
                or self.role_end <= self.role_start
                or self.solver_end <= self.solver_start):
            raise ValueError("time map needs increasing finite role and solver intervals")

    @property
    def solver_duration(self) -> float:
        return self.solver_end - self.solver_start

    @property
    def is_identity(self) -> bool:
        return self.role_start == self.solver_start and self.role_end == self.solver_end


@dataclass(frozen=True, slots=True)
class FamilyDosePortionV2:
    checkpoint_ref: str
    appraisal_ref: str
    appraisal_revision: int
    facet_id: str
    source_ref: str
    source_revision: int
    access_revision: int
    dose: tuple[float, ...]  # Ordered 8 mechanisms x (fast, residual, slow).


@dataclass(frozen=True, slots=True)
class FamilyDoseShareV3:
    """One block's explicit fraction of one family contribution's 24D dose."""

    checkpoint_ref: str
    appraisal_ref: str
    appraisal_revision: int
    facet_id: str
    source_ref: str
    source_revision: int
    access_revision: int
    contribution_dose: tuple[float, ...]
    share: float


@dataclass(frozen=True, slots=True)
class BoundFamilyPortionV2:
    checkpoint_ref: str
    appraisal_ref: str
    facet_id: str
    source_ref: str
    contribution_key: str
    dose: tuple[float, ...]
    rate: tuple[float, ...]  # Constant role-time rate; identity map makes solver time equal.
    share: float = 1.0
    allocation_ref: str = ""


@dataclass(frozen=True, slots=True)
class FamilyContributionAllocationV3:
    event_ref: str
    contribution_key: str
    facet_id: str
    contribution_dose: tuple[float, ...]
    block_shares: tuple[tuple[str, float], ...]
    allocation_ref: str


@dataclass(frozen=True, slots=True)
class FamilyIntervalDriveCandidateV2:
    family_root: str
    time_map: AffineTimeMapV1
    role_head: str
    persona_version: int
    role_condition_version: str
    mapping_version: str
    mapping_compiler_ref: str
    policy_version: str
    graph_epoch: int
    portions: tuple[BoundFamilyPortionV2, ...]
    family_dose_l1: float
    read_versions: tuple[GraphVersion, ...]
    source_closure_digest: str
    candidate_digest: str
    contribution_allocations: tuple[FamilyContributionAllocationV3, ...] = ()
    schema: str = SCHEMA
    status: str = "HOLD"
    missing_inputs: tuple[str, ...] = (
        "authenticated_d04_appraisal_acceptance_receipt",
        "authenticated_d04_semantic_mapping_acceptance_receipt",
        "w01_authenticated_installed_identity_time_mapping",
        "calibrated_d04_family_dose_and_role_condition_authority",
        "w01_complete_current_family_and_drive_inventory_with_fence",
        "w01_atomic_contribution_consumption_and_numeric_adoption",
    )


def compile_family_interval_drive_candidate(
    *, snapshot: GraphSnapshot, namespace: NamespaceId,
    role: ActiveRoleQualification, condition: RoleCondition,
    policy: CompiledDrivePolicy, time_map: AffineTimeMapV1,
    portions: tuple[FamilyDosePortionV2 | FamilyDoseShareV3, ...],
    audience: tuple[str, ...], purpose: str,
) -> FamilyIntervalDriveCandidateV2:
    """Bind explicit 24D doses to graph facts and divide by role duration.

    Doses are caller-supplied semantic *claims*, not inferred from source text.
    The mapping acceptance receipt is absent from the installed schema, hence
    even a structurally valid result is HOLD and is not a product drive row.
    """
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(role) is not ActiveRoleQualification
            or type(condition) is not RoleCondition or type(policy) is not CompiledDrivePolicy
            or type(time_map) is not AffineTimeMapV1
            or type(portions) is not tuple or not portions
            or type(audience) is not tuple or not audience
            or any(type(x) is not str or not x or x == "*" for x in audience)
            or purpose not in {"context", "expression", "consolidation", "audit"}):
        raise FamilyDriveHold("typed graph, role, mapping, time and portions are required")
    # The installed block operator and FixedBlockStep both use role time. A
    # scaled/offset solver clock would also require mapping K/R/J and step
    # length; a rate conversion alone would silently change the dynamics.
    if not time_map.is_identity:
        raise FamilyDriveHold("nonidentity time map lacks operator and step conversion")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or role.namespace != namespace or role.graph_epoch != snapshot.epochs[0].revision
            or role.head_id != condition.role_ref
            or policy.condition_version != condition.condition_version
            or policy.policy_version != condition.policy_version
            or condition.persona_version != str(role.plan.version)):
        raise FamilyDriveHold("D01 role, mapping or graph epoch is stale")
    versions = list(role.read_versions)
    for version in versions:
        atom = snapshot.get(version.key)
        if atom is None or not atom.valid or atom.revision != version.revision:
            raise FamilyDriveHold("D01 installed role read is absent or stale")

    source_rows: dict[str, SourceRecord] = {}
    source_evidence: set[tuple[str, int, str, bool]] = set()
    active: set[str] = set()

    def qualify_source(ref: str) -> SourceRecord:
        if ref in active:
            raise FamilyDriveHold("D06 source ancestry cycle")
        if ref in source_rows:
            return source_rows[ref]
        if len(source_rows) + len(active) >= 256:
            raise FamilyDriveHold("D06 source ancestry exceeds bound")
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise FamilyDriveHold("D06 source ref is invalid") from exc
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise FamilyDriveHold("D06 source crosses namespace or type")
        access_ref = access_key(*namespace.as_tuple, key.owner.subject)
        head_ref = source_correction_head_key(namespace, key.owner.subject)
        source, access, head = (snapshot.get(k) for k in (key, access_ref, head_ref))
        if (source is None or not source.valid or source.revision < 1
                or access is None or not access.valid or access.revision < 1
                or head is None or head.valid or head.revision != 0):
            raise FamilyDriveHold("D06 source, access or correction head is absent or stale")
        try:
            record = SourceRecord.from_dict(source.value)
            validate_access(access.value)
        except (TypeError, ValueError) as exc:
            raise FamilyDriveHold("D06 source or access value is malformed") from exc
        if (record.source_id != key.owner.subject
                or access.value["source_id"] != record.source_id
                or access.value["status"] != "active"
                or purpose not in record.purposes or purpose not in access.value["purposes"]
                or not set(audience).issubset(record.audiences)
                or not set(audience).issubset(access.value["audiences"])):
            raise FamilyDriveHold("D06 source or ancestor access is revoked or unauthorized")
        active.add(ref)
        for parent in record.parent_source_ids:
            qualify_source(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        source_rows[ref] = record
        for atom in (source, access, head):
            versions.append(GraphVersion(atom.key, atom.revision))
            source_evidence.add((atom.key.token, atom.revision,
                                 canonical_digest(atom.value), atom.valid))
        return record

    family_root: str | None = None
    claims: dict[tuple[str, str, str], list[tuple[BoundFamilyPortionV2, tuple[float, ...], float, bool]]] = {}
    bound: list[BoundFamilyPortionV2] = []
    for portion in portions:
        shared = type(portion) is FamilyDoseShareV3
        if not shared and type(portion) is not FamilyDosePortionV2:
            raise FamilyDriveHold("every portion must use the v2 or v3 typed contract")
        try:
            checkpoint_key = AtomKey.from_token(portion.checkpoint_ref)
            appraisal_key = AtomKey.from_token(portion.appraisal_ref)
        except (TypeError, ValueError) as exc:
            raise FamilyDriveHold("checkpoint or appraisal ref is invalid") from exc
        if (checkpoint_key.type_name not in {"d04.numeric_checkpoint.v1", "d04.numeric_checkpoint.v2"}
                or checkpoint_key.owner.kind != "persona"
                or appraisal_key.type_name != "d04.appraisal_bundle.v1"
                or appraisal_key.owner.kind != "event"
                or any((key.owner.bot, key.owner.persona) != namespace.as_tuple
                       for key in (checkpoint_key, appraisal_key))):
            raise FamilyDriveHold("checkpoint or appraisal crosses namespace or type")
        claim_dose = portion.contribution_dose if shared else portion.dose
        share = portion.share if shared else 1.0
        if (type(portion.appraisal_revision) is not int or portion.appraisal_revision < 1
                or type(portion.source_revision) is not int or portion.source_revision < 1
                or type(portion.access_revision) is not int or portion.access_revision < 1
                or type(claim_dose) is not tuple or len(claim_dose) != len(REGISTERED_AXIS_IDS)
                or any(type(x) not in (int, float) or not math.isfinite(x)
                       for x in claim_dose)
                or type(share) not in (int, float) or not math.isfinite(share)
                or not 0 < share <= 1):
            raise FamilyDriveHold("portion needs positive revisions and finite ordered 8x3 dose")
        checkpoint, appraisal_atom = snapshot.get(checkpoint_key), snapshot.get(appraisal_key)
        if checkpoint is None or not checkpoint.valid or checkpoint.revision < 1:
            raise FamilyDriveHold("D04 checkpoint is absent")
        if (appraisal_atom is None or not appraisal_atom.valid
                or appraisal_atom.revision != portion.appraisal_revision):
            raise FamilyDriveHold("D04 appraisal is absent or stale")
        try:
            appraisal = _decode_appraisal(appraisal_atom.value)
        except (TypeError, ValueError) as exc:
            raise FamilyDriveHold("D04 appraisal value is malformed") from exc
        if (appraisal_key.owner.subject != appraisal.event_ref
                or appraisal_key.name != appraisal.appraisal_id):
            raise FamilyDriveHold("D04 appraisal identity differs from graph key")
        facets = [f for f in appraisal.meaning_facets if f.facet_id == portion.facet_id]
        if len(facets) != 1 or portion.source_ref not in facets[0].source_refs:
            raise FamilyDriveHold("D04 meaning facet does not bind source")
        if any(field in facets[0].unknown_fields
               for rule in policy.rules for field in rule.required_known_fields):
            raise FamilyDriveHold("D04 appraisal has unresolved required semantic fields")
        record = qualify_source(portion.source_ref)
        source_key_ = AtomKey.from_token(portion.source_ref)
        source_atom = snapshot.get(source_key_)
        access_atom = snapshot.get(access_key(*namespace.as_tuple, record.source_id))
        if (source_atom.revision != portion.source_revision
                or access_atom.revision != portion.access_revision):
            raise FamilyDriveHold("D06 source or access revision differs from portion")
        if (_REALITY[record.source_kind]
                != (appraisal.source_family, appraisal.content_reality)
                or record.recorded_at > appraisal.learned_at):
            raise FamilyDriveHold("D04 appraisal reality or learning time differs from source")
        if family_root is None:
            family_root = record.provenance_root
        elif family_root != record.provenance_root:
            raise FamilyDriveHold("portions mix D06 provenance families")
        claim = (appraisal.event_ref, appraisal.contribution_key, portion.facet_id)
        contribution_dose = tuple(float(x) for x in claim_dose)
        dose = tuple(x * share for x in contribution_dose)
        rate = tuple(x / (time_map.role_end - time_map.role_start) for x in dose)
        if any(not math.isfinite(x) for x in rate):
            raise FamilyDriveHold("role-time rate overflows")
        row = BoundFamilyPortionV2(
            portion.checkpoint_ref, portion.appraisal_ref, portion.facet_id,
            portion.source_ref, appraisal.contribution_key, dose, rate, float(share),
        )
        bound.append(row)
        claims.setdefault(claim, []).append((row, contribution_dose, float(share), shared))
        versions.extend((GraphVersion(checkpoint_key, checkpoint.revision),
                         GraphVersion(appraisal_key, appraisal_atom.revision)))
    allocations: list[FamilyContributionAllocationV3] = []
    total_l1 = 0.0
    for (event_ref, contribution_key, facet_id), rows in sorted(claims.items()):
        if len(rows) > 1 and not all(shared for _, _, _, shared in rows):
            raise FamilyDriveHold("duplicate family allocation")
        if len({row.checkpoint_ref for row, _, _, _ in rows}) != len(rows):
            raise FamilyDriveHold("duplicate block share")
        contribution_dose = rows[0][1]
        if any(dose != contribution_dose for _, dose, _, _ in rows):
            raise FamilyDriveHold("contribution dose differs across block shares")
        share_total = math.fsum(share for _, _, share, _ in rows)
        if not 0.0 < share_total <= 1.0:
            raise FamilyDriveHold("block shares must have positive total at most one")
        total_l1 = math.fsum((total_l1, *(abs(x) for x in contribution_dose)))
        block_shares = tuple(sorted((row.checkpoint_ref, share)
                                    for row, _, share, _ in rows))
        allocation_ref = "d04:allocation:" + canonical_digest({
            "schema": SHARED_SCHEMA, "family": family_root,
            "claim": (event_ref, contribution_key, facet_id),
            "contribution_dose": contribution_dose,
            "block_shares": block_shares,
        })
        allocations.append(FamilyContributionAllocationV3(
            event_ref, contribution_key, facet_id, contribution_dose,
            block_shares, allocation_ref,
        ))
        for row, _, _, _ in rows:
            bound[bound.index(row)] = BoundFamilyPortionV2(
                row.checkpoint_ref, row.appraisal_ref, row.facet_id,
                row.source_ref, row.contribution_key, row.dose, row.rate,
                row.share, allocation_ref,
            )
    if total_l1 > policy.max_source_dose:
        raise FamilyDriveHold("shared source family dose budget exceeded across blocks")
    assert family_root is not None
    source_digest = canonical_digest(tuple(sorted(source_evidence)))
    ordered = tuple(sorted(bound, key=lambda p: (
        p.checkpoint_ref, p.appraisal_ref, p.facet_id, p.source_ref)))
    read_versions = tuple(dict.fromkeys(versions))
    schema = SHARED_SCHEMA if any(type(p) is FamilyDoseShareV3 for p in portions) else SCHEMA
    digest = canonical_digest({
        "schema": schema, "family": family_root, "time_map": asdict(time_map),
        "role": (role.head_id, role.plan.version, condition.condition_version),
        "mapping": (policy.mapping_version, policy.compiler_ref, policy.policy_version),
        "graph_epoch": role.graph_epoch, "source_closure": source_digest,
        "read_versions": tuple(sorted((v.key.token, v.revision) for v in read_versions)),
        "portions": tuple(asdict(p) for p in ordered),
        "contribution_allocations": tuple(asdict(a) for a in allocations),
    })
    return FamilyIntervalDriveCandidateV2(
        family_root, time_map, role.head_id, role.plan.version,
        condition.condition_version, policy.mapping_version, policy.compiler_ref,
        policy.policy_version, role.graph_epoch, ordered, total_l1,
        read_versions, source_digest, digest, tuple(allocations), schema,
    )


__all__ = [
    "AffineTimeMapV1", "FamilyDosePortionV2", "FamilyDoseShareV3",
    "BoundFamilyPortionV2", "FamilyContributionAllocationV3",
    "FamilyIntervalDriveCandidateV2", "FamilyDriveHold",
    "compile_family_interval_drive_candidate",
]
