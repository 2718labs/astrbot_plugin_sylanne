"""Installed semantic mapping of paid/adopted appraisal to all-member drives.

The fixed gain asset and Owner installation original are separate from the dose
bound policy. All canonical evidence payloads are retained, with binary64 bits.
W01 provides current qualified input and performs the resulting Graph CAS.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from decimal import Decimal
from fractions import Fraction
import json
import math
import struct

from ..domains.d04.affect import _decode_appraisal
from ..domains.d04.drive_allocation import RoleCondition
from ..domains.d04.mapping_asset_v2 import (
    SemanticMappingAssetV2, load_mapping_asset_v2, compile_untrusted_suggestion_candidate_v2,
)
from ..domains.d04.family_drive_v2 import (
    AffineTimeMapV1, FamilyDoseShareV3, compile_family_interval_drive_candidate,
)
from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from ..domains.d04.numeric_drive import SourcedNumericDrive, numeric_drive_id, sourced_numeric_drive_write
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key
from ..model_broker.d04_appraisal import (
    UntrustedAppraisalSuggestionV1, MechanismSignalSuggestionV1,
)
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .clock import get_clock_mapping, _mapping_dict
from .d04_appraisal_driver_v3 import (
    D04GraphReadV3, graph_read_rows_v3, qualify_appraisal_sources_v3,
    read_d04_appraisal_acceptance_v3, read_d04_original_v3,
    record_d04_original_in_transaction_v3, require_current_read_rows_v3,
)
from .d04_semantic_policy import AdminD04SemanticDrivePolicyV1, MECHANISMS


def evidence_payload_v3(value):
    """Canonical values for product evidence; preserve every binary64 bit."""
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("D04 evidence must contain finite binary64 values")
        return {"binary64_be": struct.pack(">d", value).hex()}
    if isinstance(value, Decimal):
        return {"decimal": str(value)}
    if isinstance(value, Fraction):
        return {"rational": [value.numerator, value.denominator]}
    if isinstance(value, AtomKey):
        return value.token
    if is_dataclass(value):
        return {name: evidence_payload_v3(getattr(value, name)) for name in value.__dataclass_fields__}
    if isinstance(value, dict):
        if any(type(k) is not str for k in value):
            raise ValueError("D04 evidence object keys must be strings")
        return {k: evidence_payload_v3(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [evidence_payload_v3(v) for v in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    raise TypeError("unsupported D04 evidence payload type")


def joint_evidence_field_v3(field: str, payload):
    """Persist the returned body alongside its digest; hashes alone are insufficient."""
    if field not in {
        "read_versions_digest", "snapshot_stamp_digest", "time_mapping_digest",
        "closure_digest", "source_closure_digest", "absent_reads_digest", "asset_digest",
        "contribution_consumption_digest", "numeric_input_digest", "full_transcript_digest",
        "family_loo_transcripts", "output_write_set_digest",
    }:
        raise ValueError("unknown D04 product evidence field")
    body = {"schema": "d04.joint-evidence." + field + ".v1",
            "payload": evidence_payload_v3(payload)}
    return body, canonical_digest(body)


@dataclass(frozen=True, slots=True)
class InstalledD04SemanticMappingV3:
    asset: SemanticMappingAssetV2
    installation_ref: str
    acceptance_ref: str
    acceptance_revision: int
    acceptance_digest: str
    allocation_policy_id: str
    allocation_policy_version: str
    block_shares: tuple[tuple[str, float], ...]

    def __post_init__(self):
        load_mapping_asset_v2(self.asset)
        if (not self.installation_ref or not self.acceptance_ref
                or type(self.acceptance_revision) is not int or self.acceptance_revision < 1
                or len(self.acceptance_digest) != 64
                or not self.allocation_policy_id or not self.allocation_policy_version
                or not self.block_shares or len({r for r, _ in self.block_shares}) != len(self.block_shares)
                or any(type(s) not in (int, float) or not math.isfinite(s) or not 0 < s <= 1
                       for _, s in self.block_shares)
                or math.fsum(s for _, s in self.block_shares) > 1):
            raise ValueError("D04 installed mapping/all-member share policy incomplete")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04RoleClockOriginalV3:
    mapping_id: str
    mapping_version: int
    registered_mapping_json: str
    clock_head_version: int
    wall_end_utc: str
    role_start: float
    role_end: float
    member_predecessor_cursors: tuple[tuple[str, float], ...]
    schema: str = "d04.current-role-clock-original.v3"


@dataclass(frozen=True, slots=True)
class D04SemanticDriveStageV3:
    namespace: NamespaceId
    original_ref: str
    original_payload_json: str
    original_digest: str
    writes: tuple
    read_versions: tuple[GraphVersion, ...]
    proofs: tuple
    family_candidates: tuple
    clock: D04RoleClockOriginalV3


def read_current_d04_role_clock_v3(
    db, *, mapping_id: str, expected_mapping_version: int,
    checkpoints: tuple, checkpoint_refs: tuple[str, ...], wall_end_utc: str,
) -> D04RoleClockOriginalV3:
    """Read the actual registered D11 mapping and require synchronized cursors."""
    if not db.in_transaction or len(checkpoints) != len(checkpoint_refs) or not checkpoints:
        raise ValueError("D04 role clock requires current complete predecessors")
    mapping = get_clock_mapping(db, mapping_id, expected_mapping_version)
    head = db.execute("SELECT max(version) FROM runtime_character_clocks WHERE mapping_id=?", (mapping_id,)).fetchone()
    if head is None or head[0] != expected_mapping_version:
        raise ValueError("D04 registered role clock head changed")
    cursors = tuple((ref, float(checkpoint.cursor)) for ref, checkpoint in zip(checkpoint_refs, checkpoints))
    start = cursors[0][1]
    if any(cursor != start for _, cursor in cursors):
        raise ValueError("D04 component has unsynchronized predecessor cursors")
    end = float(mapping.character_at(wall_end_utc))
    if not math.isfinite(end) or end <= start:
        raise ValueError("D04 role interval is not a legal current clock advance")
    return D04RoleClockOriginalV3(mapping.mapping_id, mapping.version,
        canonical_serialize(_mapping_dict(mapping)), head[0], wall_end_utc, start, end, cursors)


def require_current_d04_role_clock_v3(db, clock):
    mapping = get_clock_mapping(db, clock.mapping_id, clock.mapping_version)
    head = db.execute("SELECT max(version) FROM runtime_character_clocks WHERE mapping_id=?", (clock.mapping_id,)).fetchone()
    if (head is None or head[0] != clock.clock_head_version
            or canonical_serialize(_mapping_dict(mapping)) != clock.registered_mapping_json
            or float(mapping.character_at(clock.wall_end_utc)) != clock.role_end):
        raise ValueError("D04 current role clock original changed")


def _suggestion(raw):
    from ..model_broker.d04_appraisal import UntrustedAppraisalSuggestionV1
    return UntrustedAppraisalSuggestionV1(**{**raw,
        "bundle": _decode_appraisal(raw["bundle"]) if raw["bundle"] is not None else None,
        "mechanism_signals": tuple(MechanismSignalSuggestionV1(**{**r,
            "source_refs": tuple(r["source_refs"])}) for r in raw["mechanism_signals"]),
        "basis_refs": tuple(VersionedRef(**r) for r in raw["basis_refs"]),
        **{name: tuple(raw[name]) for name in ("possible_feelings", "unknown_fields",
                                              "source_refs", "qualified_source_refs")}})


def stage_current_d04_drive_in_transaction_v3(
    db, *, namespace: NamespaceId, appraisal_ref: str, frozen,
    snapshot, role, condition: RoleCondition,
    installed_mapping: InstalledD04SemanticMappingV3, installed_mapping_reader,
    dose_policy: AdminD04SemanticDrivePolicyV1, dose_grant_version: int,
    clock: D04RoleClockOriginalV3, audience: tuple[str, ...], purpose: str,
    interpretation_level: str,
) -> D04SemanticDriveStageV3:
    """Installed caller supplies asset port; input never includes bare signal/dose."""
    if not db.in_transaction or type(installed_mapping) is not InstalledD04SemanticMappingV3:
        raise ValueError("D04 semantic drive requires fenced installed mapping")
    # This reader is bound by the installation composition, not a command field.
    if not callable(installed_mapping_reader) or installed_mapping_reader(db, namespace) != installed_mapping:
        raise ValueError("D04 installed mapping acceptance original unavailable")
    # Only the registered installation composition supplies the policy. The
    # request has no signing key, raw policy override, or accepted grant DTO.
    graph = getattr(installed_mapping_reader, "graph", None)
    assembly = getattr(graph, "_GraphCoordinator__d04_installed_joint_assembly", None)
    issuer = getattr(graph, "_GraphCoordinator__d11_issuer", None)
    if (assembly is None or issuer is None or assembly.admin_bundle.d04_semantic_drive is not dose_policy
            or type(dose_grant_version) is not int or dose_grant_version != dose_policy.grant_version
            or assembly.installation_policy.namespace != namespace
            or assembly.installation_policy.installation_id != dose_policy.installation_id):
        raise ValueError("D04 dose authority differs from current installed composition")
    signed_grant, grant_signature = issuer.signed_budget_grant_at_version(db, dose_policy.lease_id, dose_grant_version)
    if (issuer.current_budget_grant(db, dose_policy.lease_id) != signed_grant
            or signed_grant.grant_id != dose_policy.grant_id
            or (signed_grant.bot_id, signed_grant.persona_id) != namespace.as_tuple
            or dose_policy.work_kind not in signed_grant.allowed_work_kinds):
        raise ValueError("D04 dose authority lacks the actual current signed grant")
    grant_json, stored_signature = db.execute("SELECT grant_json,signature FROM runtime_budget_grants "
        "WHERE lease_id=? AND version=?", (dose_policy.lease_id, dose_grant_version)).fetchone()
    if stored_signature != grant_signature:
        raise ValueError("D04 signed grant original changed in transaction")
    policy_payload = {name: dict(getattr(dose_policy, name)) if name.startswith("mechanism_max_")
        else asdict(dose_policy.namespace) if name == "namespace" else getattr(dose_policy, name)
        for name in dose_policy.__dataclass_fields__}
    signed_budget_grant = {"kind": "budget-grant.v1", "payload_json": grant_json, "signature": grant_signature}
    acceptance = _read_mapping_appraisal_acceptance_v1(db, namespace, appraisal_ref, issuer)
    if acceptance is None:
        raise ValueError("D04 appraisal is not adopted")
    appraisal_atom = snapshot.get(AtomKey.from_token(appraisal_ref))
    if (appraisal_atom is None or not appraisal_atom.valid
            or appraisal_atom.revision != acceptance.appraisal_revision
            or canonical_serialize(appraisal_atom.value) != acceptance.appraisal_value_json):
        raise ValueError("D04 adopted appraisal graph original changed")
    from .d06_life_numeric_task_v1 import LifeNumericAppraisalAcceptanceV1, read_life_numeric_paid_cost_for_acceptance_v1
    if type(acceptance) is LifeNumericAppraisalAcceptanceV1:
        original_cost = read_life_numeric_paid_cost_for_acceptance_v1(db, acceptance, issuer)
    else:
        original_cost = read_d04_original_v3(db, namespace, "appraisal_cost", acceptance.cost_original_ref)
    if original_cost is None or original_cost[1] != acceptance.cost_original_digest or original_cost[0]["paid"] is not True:
        raise ValueError("D04 adopted appraisal lacks fully paid original")
    source_versions, family_by_ref = qualify_appraisal_sources_v3(snapshot, frozen, audience=audience, purpose=purpose)
    suggestion = _suggestion(json.loads(acceptance.suggestion_json))
    mapping = compile_untrusted_suggestion_candidate_v2(installed_mapping.asset, condition,
        suggestion, interpretation_level=interpretation_level, source_family_by_ref=family_by_ref)
    if mapping.policy is None or mapping.held_reasons:
        raise ValueError("D04 semantic mapping uncovered: " + ",".join(mapping.held_reasons))
    require_current_d04_role_clock_v3(db, clock)
    member_refs = tuple(ref for ref, _ in clock.member_predecessor_cursors)
    share_by_ref = dict(installed_mapping.block_shares)
    if set(share_by_ref) != set(member_refs):
        raise ValueError("D04 installed allocation must cover the whole component")
    original_ref = "d04-mapping:" + canonical_digest({"appraisal_acceptance": acceptance.digest,
        "mapping_installation": installed_mapping.digest, "clock": evidence_payload_v3(clock)})
    for family in set(d.family_root for d in mapping.contribution_doses):
        family_share = math.fsum(share_by_ref.values())
        for contribution in (d for d in mapping.contribution_doses if d.family_root == family):
            for i, mechanism in enumerate(MECHANISMS):
                dose_policy.validate_share(mechanism, tuple(contribution.dose[i * 3:i * 3 + 3]), family_share)
    families = []
    # Only the adopted broker signal is used; no public parameter can set doses.
    aggregate = {}
    for family in sorted({d.family_root for d in mapping.contribution_doses}):
        portions = []
        for contribution in (d for d in mapping.contribution_doses if d.family_root == family):
            facet = next(f for f in suggestion.bundle.meaning_facets if f.facet_id == contribution.facet_id)
            refs = sorted(ref for ref in facet.source_refs if family_by_ref[ref] == family)
            if not refs:
                raise ValueError("D04 mapped contribution missing source family")
            # Several records in a family describe one dose. Keep the complete
            # closure in the original, use one stable record for numeric identity.
            source_ref = refs[0]
            source_key = AtomKey.from_token(source_ref)
            source_atom = snapshot.get(source_key)
            access_atom = snapshot.get(access_key(*namespace.as_tuple, source_key.owner.subject))
            for member_ref in member_refs:
                portions.append(FamilyDoseShareV3(member_ref, appraisal_ref,
                    acceptance.appraisal_revision, facet.facet_id, source_ref,
                    source_atom.revision, access_atom.revision, contribution.dose,
                    share_by_ref[member_ref]))
        candidate = compile_family_interval_drive_candidate(snapshot=snapshot, namespace=namespace,
            role=role, condition=condition, policy=mapping.policy,
            time_map=AffineTimeMapV1(clock.role_start, clock.role_end, clock.role_start, clock.role_end,
                                    mapping_ref=clock.mapping_id + ":" + str(clock.mapping_version)),
            portions=tuple(portions), audience=audience, purpose=purpose)
        families.append(candidate)
        for portion in candidate.portions:
            identity = (portion.checkpoint_ref, portion.source_ref)
            vector = aggregate.setdefault(identity, [0.0] * 24)
            for axis, rate in enumerate(portion.rate):
                vector[axis] = math.fsum((vector[axis], rate))
    writes = []
    versions = {v.key: v for v in (*role.read_versions, *source_versions,
        GraphVersion(AtomKey.from_token(appraisal_ref), acceptance.appraisal_revision))}
    for candidate in families:
        versions.update((v.key, v) for v in candidate.read_versions)
    for (member_ref, source_ref), vector in sorted(aggregate.items()):
        checkpoint = snapshot.get(AtomKey.from_token(member_ref))
        source = snapshot.get(AtomKey.from_token(source_ref))
        access_ref = access_key(*namespace.as_tuple, AtomKey.from_token(source_ref).owner.subject)
        access = snapshot.get(access_ref)
        drive = SourcedNumericDrive(numeric_drive_id(member_ref, source_ref, clock.role_start, clock.role_end),
            1, member_ref, checkpoint.revision, source_ref, source.revision, access_ref.token,
            access.revision, installed_mapping.asset.policy_version, original_ref, SCHEME_VERSION,
            clock.role_start, clock.role_end, REGISTERED_AXIS_IDS, tuple(vector))
        write = sourced_numeric_drive_write(drive)
        absent = snapshot.get(write.key)
        if absent is None or absent.revision != 0 or absent.valid:
            raise ValueError("D04 drive requires actual absent CAS read")
        versions[write.key] = GraphVersion(write.key, 0)
        writes.append(write)
    rows = graph_read_rows_v3(snapshot, tuple(versions.values()))
    require_current_read_rows_v3(db, rows, namespace)
    dose_kind = "d11.installed-d04-semantic-dose-policy.v3"
    dose_authority_body = {"schema": dose_kind, "namespace": asdict(namespace),
        "installation_id": dose_policy.installation_id,
        "manifest_digest": installed_mapping_reader.manifest_sha256,
        "mapping_original_ref": original_ref, "mapping_acceptance_digest": installed_mapping.acceptance_digest,
        "appraisal_acceptance_digest": acceptance.digest, "dose_policy": policy_payload,
        "signed_budget_grant": signed_budget_grant}
    dose_authority_json = canonical_serialize(dose_authority_body)
    dose_authority = {"kind": dose_kind, "payload_json": dose_authority_json,
        "signature": issuer._signer.sign(dose_kind, dose_authority_json)}
    payload = {"schema": "d04.semantic_mapping_acceptance.v3", "namespace": asdict(namespace),
        "dose_policy": policy_payload, "signed_budget_grant": signed_budget_grant,
        "dose_policy_authority": dose_authority,
        "appraisal_acceptance_ref": appraisal_ref, "appraisal_acceptance_digest": acceptance.digest,
        "mapping_installation": asdict(installed_mapping), "mapping_installation_digest": installed_mapping.digest,
        "role": asdict(role), "condition": asdict(condition), "clock": asdict(clock),
        "interpretation_level": interpretation_level,
        "mapping_candidate": asdict(mapping), "family_candidates": [asdict(f) for f in families],
        "read_rows": [asdict(row) for row in rows], "source_family_by_ref": family_by_ref,
        "unknown_fields": {f.facet_id: f.unknown_fields for f in suggestion.bundle.meaning_facets},
        "output_writes": [asdict(w) for w in writes]}
    wire = canonical_serialize(payload)
    return D04SemanticDriveStageV3(namespace, original_ref, wire, canonical_digest(payload),
        tuple(writes), tuple(versions.values()), (acceptance, installed_mapping), tuple(families), clock)


def record_d04_mapping_acceptance_after_cas_v3(db, stage,*,drive_commit_witness_v3=None):
    if drive_commit_witness_v3 is not None:
        from .d06_life_numeric_drive_v1 import record_current_drive_mapping_original_v3
        return record_current_drive_mapping_original_v3(db,stage,drive_commit_witness_v3)
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is not None and reader.operation_kind=="prepare_internal_life_numeric_drive":
        raise ValueError("selected Drive mapping record requires actual ACTIVE WRITE witness")
    if not db.in_transaction:
        raise ValueError("D04 mapping record requires same fenced CAS transaction")
    for write in stage.writes:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[0] != 1 or row[2] != 1 or json.loads(row[1]) != write.value:
            raise ValueError("D04 mapping acceptance precedes drive CAS")
    require_current_d04_role_clock_v3(db, stage.clock)
    digest = record_d04_original_in_transaction_v3(db, stage.namespace, "semantic_mapping",
        stage.original_ref, json.loads(stage.original_payload_json))
    if digest != stage.original_digest:
        raise ValueError("D04 mapping original digest differs")
    return digest


def read_d04_mapping_acceptance_v3(db, namespace, original_ref):
    return read_d04_original_v3(db, namespace, "semantic_mapping", original_ref)


@dataclass(frozen=True, slots=True)
class D04JointEvidenceInputsV3:
    namespace: NamespaceId
    component_digest: str
    member_refs: tuple[str, ...]
    field_payloads: tuple[tuple[str, str], ...]
    read_rows: tuple[D04GraphReadV3, ...]
    clock: D04RoleClockOriginalV3
    schema: str = "d04.frozen-joint-evidence-inputs.v3"


@dataclass(frozen=True, slots=True)
class D04ProductEvidencePayloadsV3:
    inputs: D04JointEvidenceInputsV3
    payloads: tuple[tuple[str, str], ...]
    digests: tuple[tuple[str, str], ...]
    family_loo_transcripts: tuple[tuple[str, str], ...]
    schema: str = "d04.product-evidence-payloads.v3"

    def evidence_fields(self):
        return {**dict(self.digests), "family_loo_transcripts": self.family_loo_transcripts}


def freeze_current_d04_joint_evidence_inputs_v3(
    db, preparation, *, clock: D04RoleClockOriginalV3, installed_output_policy,
    installed_mapping_reader,
) -> D04JointEvidenceInputsV3:
    """Derive all graph/clock/asset/family payloads from one current pinned read.

    Includes invalid numeric rows and true negative heads. No argument accepts
    an evidence digest. installed_mapping_reader is the composition-owned port.
    The numeric ABI payload and transcripts are appended from the actual run.
    """
    from .joint_numeric_component import MAX_ROWS
    current, snapshot = preparation.current, preparation.snapshot
    component, namespace = current.component, current.component.namespace
    if not db.in_transaction or component.query_epoch.revision != snapshot.epochs[0].revision:
        raise ValueError("D04 evidence needs the same complete fenced snapshot")
    require_current_d04_role_clock_v3(db, clock)
    if ((clock.role_start, clock.role_end) != (component.role_start, component.role_end)
            or tuple(ref for ref, _ in clock.member_predecessor_cursors) != component.checkpoint_refs):
        raise ValueError("D04 evidence role mapping differs from actual member cursors")
    # Exactly the typed numeric inventory predicate used by the collector;
    # an invalid row is preserved rather than being counted as absence.
    type_names = tuple(sorted({AtomKey.from_token(r).type_name for r in component.checkpoint_refs})) + (
        "d04.numeric_coupling.v1", "d04.sourced_numeric_drive.v1")
    placeholders = ",".join("?" for _ in type_names)
    scan = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        f"AND type_name IN ({placeholders}) ORDER BY token LIMIT ?",
        (*namespace.as_tuple, *type_names, MAX_ROWS + 1)).fetchall()
    if len(scan) > MAX_ROWS:
        raise ValueError("D04 evidence numeric scan is incomplete")
    rows = graph_read_rows_v3(snapshot, snapshot.versions)
    require_current_read_rows_v3(db, rows, namespace)
    by_ref = {r.ref: r for r in rows}
    scan_rows = tuple(D04GraphReadV3(ref, revision, bool(valid), canonical_serialize(json.loads(value)))
                      for ref, revision, value, valid in scan)
    if any(by_ref.get(row.ref) != row for row in scan_rows):
        raise ValueError("D04 snapshot omitted actual numeric scan row")
    mappings = {}
    accepted = {}
    for drive in current.drives:
        mapping = read_d04_mapping_acceptance_v3(db, namespace, drive.mapping_compiler_ref)
        if mapping is None:
            raise ValueError("D04 actual drive lacks installed mapping acceptance original")
        raw, digest = mapping
        if (raw["namespace"] != asdict(namespace)
                or (raw["clock"]["role_start"], raw["clock"]["role_end"]) != (component.role_start, component.role_end)):
            raise ValueError("D04 drive mapping original interval/scope differs")
        installed = installed_mapping_reader(db, namespace)
        if installed is None or installed.digest != raw["mapping_installation_digest"]:
            raise ValueError("D04 installed mapping changed before numeric work")
        matching = [w for w in raw["output_writes"] if w["value"]["drive_id"] == drive.drive_id]
        if len(matching) != 1 or matching[0]["value"] != asdict(drive):
            # dataclass tuples are lists in durable JSON; canonical serialization
            # compares those intentional representations without Python repr.
            if len(matching) != 1 or canonical_serialize(matching[0]["value"]) != canonical_serialize(asdict(drive)):
                raise ValueError("D04 actual numeric drive differs from mapping-issued write")
        appraisal_ref = raw["appraisal_acceptance_ref"]
        graph = getattr(installed_mapping_reader, 'graph', None)
        issuer = getattr(graph, '_GraphCoordinator__d11_issuer', None)
        appraisal = _read_mapping_appraisal_acceptance_v1(db, namespace, appraisal_ref, issuer)
        if appraisal is None or appraisal.digest != raw["appraisal_acceptance_digest"]:
            raise ValueError("D04 mapped appraisal acceptance original changed")
        mappings[drive.mapping_compiler_ref] = {"ref": drive.mapping_compiler_ref, "digest": digest, "payload": raw}
        accepted[appraisal_ref] = {"ref": appraisal_ref, "digest": appraisal.digest, "payload": asdict(appraisal)}
    metadata = db.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if metadata is None or metadata[2] != component.graph_revision:
        raise ValueError("D04 actual snapshot stamp missing")
    stamp = {"namespace": asdict(namespace), "catalogue": component.catalogue_hash,
        "graph_incarnation": component.graph_incarnation, "graph_revision": component.graph_revision,
        "query_epoch": asdict(component.query_epoch), "access_epoch": component.access_epoch,
        "delete_epoch": component.delete_epoch, "schema": metadata[0],
        "requirements": json.loads(metadata[1])}
    source_rows = tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in {
        "memory.source", "memory.access", "d06.source_correction_head.v1"})
    allocation_rows = []
    for mapping in mappings.values():
        raw = mapping["payload"]
        for family in raw["family_candidates"]:
            for allocation in family["contribution_allocations"]:
                allocation_rows.append({"family_root": family["family_root"],
                    "allocation": allocation, "role_start": family["time_map"]["role_start"],
                    "role_end": family["time_map"]["role_end"],
                    "mapping_ref": mapping["ref"], "mapping_digest": mapping["digest"],
                    "current_ledger_reads": [asdict(r) for r in rows
                        if AtomKey.from_token(r.ref).type_name == "d04.contribution_ledger.v1"]})
    if not allocation_rows:
        raise ValueError("D04 evidence lacks all-member family allocation originals")
    payloads = {
        "read_versions_digest": {"versions": [{"ref": r.ref, "revision": r.revision} for r in rows]},
        "snapshot_stamp_digest": stamp,
        "time_mapping_digest": asdict(clock),
        "closure_digest": {"snapshot_stamp": stamp, "ordered_members": component.checkpoint_refs,
            "numeric_scan_rows": [asdict(r) for r in scan_rows], "couplings": component.edges,
            "block_drives": component.block_drives,
            "coverage": {"predicate": {"namespace": asdict(namespace), "type_names": type_names},
                "ordering": "token_ascending", "limit": MAX_ROWS, "count": len(scan), "complete": True}},
        "source_closure_digest": {"source_rows": [asdict(r) for r in source_rows],
            "audience": preparation.envelope.authority.audience,
            "purpose": preparation.envelope.authority.purpose,
            "families": current.families, "appraisal_originals": tuple(accepted[k] for k in sorted(accepted)),
            "mapping_originals": tuple(mappings[k] for k in sorted(mappings))},
        "absent_reads_digest": {"absent_rows": [asdict(r) for r in rows if r.revision == 0],
            "negative_numeric_inventory": {"predicate": type_names, "complete": True, "count": len(scan)}},
        "asset_digest": {"catalogue": component.catalogue_hash,
            "checkpoint_assets": tuple((ref, cp.assets) for ref, cp in zip(component.checkpoint_refs, current.checkpoints)),
            "member_order": component.checkpoint_refs, "axis_order": REGISTERED_AXIS_IDS,
            "mapping_assets": tuple(mappings[k]["payload"]["mapping_installation"] for k in sorted(mappings)),
            "output_policy": installed_output_policy.policy,
            "output_policy_sha256": installed_output_policy.policy_sha256,
            "manifest_sha256": installed_output_policy.manifest_sha256},
        "contribution_consumption_digest": {"allocation_rows": allocation_rows},
    }
    return D04JointEvidenceInputsV3(namespace, component.candidate_digest, component.checkpoint_refs,
        tuple((field, canonical_serialize(joint_evidence_field_v3(field, payload)[0]))
              for field, payload in sorted(payloads.items())), rows, clock)


def _native_transcript_payload_v3(transcript):
    """Recompute the existing fixed-block typed serializer, including actual ABI input."""
    from ..native_runtime.fixed_block_transcript import _digest, FixedBlockTrajectoryMathTranscript
    if type(transcript) is FixedBlockTrajectoryMathTranscript:
        from ..native_runtime.d04_fixed_trajectory_v2 import verify_d04_fixed_trajectory_v2, compact_d04_fixed_trajectory_v2
        verify_d04_fixed_trajectory_v2(transcript)
        body = {"schema": "abi2.fixed-block-trajectory-math-transcript.v1",
            "initial_error": transcript.initial_error, "final_error": transcript.final_error,
            "production_binding": asdict(transcript.production_binding),
            "steps": [step.transcript_sha256 for step in transcript.steps]}
        if _digest(body) != transcript.transcript_sha256:
            raise ValueError("D04 complete trajectory native commitment differs")
        return {"typed_serializer_body": body,
            "complete_trajectory": compact_d04_fixed_trajectory_v2(transcript),
            "transcript_sha256": transcript.transcript_sha256}
    if transcript.input.digest() != transcript.input_sha256 or _digest(transcript.output) != transcript.output_sha256:
        raise ValueError("D04 actual ABI transcript input/output digest differs")
    body = {"schema": "abi2.fixed-block-math-transcript.v1",
        "input_sha256": transcript.input_sha256, "output_sha256": transcript.output_sha256,
        "manifest_sha256": transcript.production_binding.manifest_sha256,
        "native_sha256": transcript.production_binding.native_sha256, "bounds": asdict(transcript.bounds)}
    if _digest(body) != transcript.transcript_sha256:
        raise ValueError("D04 actual ABI transcript cannot be rederived")
    return {"typed_serializer_body": body,
        "actual_input": evidence_payload_v3(transcript.input),
        "actual_output": evidence_payload_v3(transcript.output),
        "transcript_sha256": transcript.transcript_sha256}


def build_d04_product_evidence_payloads_v3(inputs, product) -> D04ProductEvidencePayloadsV3:
    """Append true ABI2 input/full/LOO/output originals, never accept caller hashes."""
    current = product.preparation.current
    math_result, output = product.replay.math_result, product.output
    if (inputs.component_digest != current.component.candidate_digest
            or inputs.member_refs != output.member_refs or math_result.full_transcript is None):
        raise ValueError("D04 evidence product differs from frozen current input")
    originals = getattr(math_result, "family_transcript_originals", None)
    if originals is None:
        originals = getattr(math_result, "family_transcript_originals_v3", None)
    if originals is None or tuple(f for f, _ in originals) != tuple(f for f, _ in math_result.family_transcripts):
        raise ValueError("D04 true per-family ABI2 transcript originals unavailable")
    full = _native_transcript_payload_v3(math_result.full_transcript)
    if full["transcript_sha256"] != product.replay.candidate.full_transcript_sha256:
        raise ValueError("D04 full native original differs from receipt")
    loo = tuple((family, _native_transcript_payload_v3(original)) for family, original in originals)
    if tuple((f, original["transcript_sha256"]) for f, original in loo) != product.replay.candidate.family_transcripts:
        raise ValueError("D04 removal native originals differ from receipt")
    payloads = dict(inputs.field_payloads)
    # Native fields retain their already-versioned fixed-block serializer. This
    # is the typed serializer branch of backend contract 4.3, not a caller hash.
    payloads["full_transcript_digest"] = canonical_serialize(full)
    payloads["family_loo_transcripts"] = canonical_serialize(loo)
    numeric = {"ordered_members": inputs.member_refs, "ordered_axes": REGISTERED_AXIS_IDS,
        "abi2_full_input": math_result.full_step,
        "trajectory_schema": math_result.trajectory_schema,
        "complete_step_sizes": tuple(step.input.h for step in math_result.full_transcript.steps),
        "member_initial_boxes": tuple((ref, cp.certified_box, cp.numeric_error_bound)
            for ref, cp in zip(inputs.member_refs, current.checkpoints)),
        "family_removal_inputs": tuple((family, original.input) for family, original in originals)}
    numeric_body, numeric_digest = joint_evidence_field_v3("numeric_input_digest", numeric)
    payloads["numeric_input_digest"] = canonical_serialize(numeric_body)
    from ..domains.d04.joint_state_output_v1 import _write_set
    # This field uses the existing joint-output serializer, just as native
    # transcript fields use theirs. Retain exact raw write rows and separately
    # preserve binary64 output evidence; never hash a wrapper in place of the
    # W01 write-set commitment.
    output_rows = _write_set(output.members)
    output_digest = canonical_digest(output_rows)
    if output_digest != output.write_set_digest:
        raise ValueError("D04 issued output write set differs from its typed serializer")
    payloads["output_write_set_digest"] = canonical_serialize({
        "schema": "d04.joint-output-write-set-original.v3",
        "typed_serializer_body": output_rows,
        "write_set_digest": output_digest,
        "output_original": evidence_payload_v3(output)})
    digests = {field: canonical_digest(json.loads(wire)) for field, wire in inputs.field_payloads}
    digests.update(numeric_input_digest=numeric_digest, output_write_set_digest=output_digest,
                   full_transcript_digest=full["transcript_sha256"])
    return D04ProductEvidencePayloadsV3(inputs, tuple(sorted(payloads.items())),
        tuple(sorted(digests.items())), product.replay.candidate.family_transcripts)


def record_d04_joint_evidence_payloads_in_transaction_v3(db, operation_id, payloads):
    if not db.in_transaction:
        raise ValueError("D04 evidence payloads require fenced adoption transaction")
    return record_d04_original_in_transaction_v3(db, payloads.inputs.namespace,
        "joint_evidence_payloads", operation_id, asdict(payloads))


def _read_mapping_appraisal_acceptance_v1(db, namespace, appraisal_ref, issuer):
    """Two closed adopted-original families; neither reader issues authority."""
    from .d06_life_numeric_task_v1 import read_life_numeric_appraisal_acceptance_v1
    from .issuers import D11BudgetJobIssuer
    old = read_d04_appraisal_acceptance_v3(db, namespace, appraisal_ref)
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_d11_life_originals_v1'").fetchone() is None:
        return old
    if db.execute("SELECT 1 FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?", (*namespace.as_tuple, appraisal_ref)).fetchone() is None:
        return old
    if type(issuer) is not D11BudgetJobIssuer:
        raise ValueError('numeric mapping appraisal requires the actual installed D11 issuer')
    numeric = read_life_numeric_appraisal_acceptance_v1(db, namespace, appraisal_ref, issuer)
    if old is not None and numeric is not None:
        raise ValueError('mapping appraisal has ambiguous original families')
    return numeric if numeric is not None else old
