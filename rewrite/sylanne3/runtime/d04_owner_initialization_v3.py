"""Owner-authenticated producers for the installed D04 authored first-use path.

Public inputs are author intent only. W01 rereads the signed Owner/session and
current graph under its retained Authority write fence. Budget allocation splits
an existing installation root lease; it never seeds another budget balance.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import math
from uuid import UUID

from ..contracts import Event, Scope, canonical_json
from ..graph_store import GraphStore, ProductionGraphStore
from ..graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, owner_grant_key
from ..runtime_contracts import AuthorityContext, canonical_digest, canonical_serialize
from ..domains.d12.types import (
    ActiveSchemeHeadV1, CharacterDraft, active_scheme_head_key, character_draft_key,
)
from .budget import BudgetLease, create_budget_lease, get_budget_lease, _amounts
from .d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3
from .d12_domain_scheme_compile_v1 import _authored_root_blocks_v3
from .issuers import BudgetLeaseGrant


ROOT_FIELD = "d04.authored_root"
DRAFT_SCHEMA = "d04.owner_root_draft_original.v3"
BUDGET_SCHEMA = "d04.owner_root_budget_original.v3"
TOPOLOGY_SCHEMA = "d04.owner_root_coupling_original.v3"
TOPOLOGY_ID = "d04.authored_root_mood_feeling_same_axis.v3"
TOPOLOGY_ACTIVITY = "d04.authored_root_coupling.v3"


def _operation(operation_id):
    try:
        parsed = UUID(operation_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("canonical UUID4 Owner operation required") from exc
    if parsed.version != 4 or str(parsed) != operation_id:
        raise ValueError("canonical UUID4 Owner operation required")


def _installation(c, authority):
    from ..graph_coordinator import GraphCoordinator, UnavailableGuard
    from ..host.installed_d04_root_resources import load_installed_d04_root_preset_v3
    if (type(c) is not GraphCoordinator or type(authority) is not AuthorityContext
            or authority.issuer_domain != "d12" or "persona" not in authority.owner_scope
            or not isinstance(c._GraphCoordinator__store, ProductionGraphStore)):
        raise UnavailableGuard("installed D12 Owner root producer unavailable")
    assembly = c._GraphCoordinator__d04_installed_joint_assembly
    port = c._GraphCoordinator__content_fence_v2
    if (assembly is None or port is None
            or assembly.installation_policy.namespace != authority.namespace
            or port.installation_grant.installation_id != assembly.installation_policy.installation_id
            or port.installation_grant.manifest_digest != assembly.installation_policy.manifest_digest):
        raise UnavailableGuard("current installed D04 root authority differs")
    preset = load_installed_d04_root_preset_v3(assembly.package_root,
        assembly.installation_policy.manifest_digest,
        available_cpu_features=assembly.available_cpu_features)
    return assembly, preset


def _row(db, store, key, *, optional=False):
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
    if row is None and optional:
        return None
    if row is None or row[0] < 1 or row[2] != 1:
        raise ValueError("current Owner root prerequisite is absent or invalid")
    value = json.loads(row[1])
    if canonical_json(value) != row[1]:
        raise ValueError("Owner root prerequisite is not canonical")
    store._registry.validate(key, value)
    return row[0], value


def _commit_graph(c, db, metadata, epoch, now, operation_id, activity, request_digest, reads, writes):
    store, cap = c._GraphCoordinator__store, c._GraphCoordinator__graph_capability
    candidate = GraphCandidate(Event(Scope(*metadata.requirements.namespace.as_tuple, activity),
        operation_id, now, activity, {"request_digest": request_digest}),
        tuple(sorted(reads, key=lambda item: item.key.token)),
        tuple(sorted(writes, key=lambda item: item.key.token)), (epoch,))
    receipt = GraphStore._graph_commit_in_transaction(store, candidate, _capability=cap)
    expected = {GraphVersion(write.key, next(item.revision for item in reads if item.key == write.key) + 1)
                for write in writes}
    if receipt.status != "committed" or set(receipt.revisions) != expected or receipt.invalidated:
        raise ValueError("Owner root graph CAS or invalidation differs")
    store.cas_graph_recovery_metadata(metadata, metadata.requirements, _capability=cap)
    return {"status": receipt.status,
        "revisions": [[item.key.token, item.revision] for item in receipt.revisions],
        "invalidated": [], "epoch": asdict(receipt.epoch)}


def initialize_current_d04_root_draft_v3(c, authority, lease, *, operation_id, root_field: dict):
    """Add one installed root choice without discarding existing D12 fields.

    Editing an existing draft does not activate it or advance its current head.
    The later compiled root adoption owns that transition. On a blank namespace
    this creates the same initial administrative head used by other draft paths.
    """
    _operation(operation_id)
    # Validate before allocating a durable attempt, and detach all nested input.
    _authored_root_blocks_v3(root_field)
    field = json.loads(canonical_serialize(root_field))
    _installation(c, authority)
    namespace, store = authority.namespace, c._GraphCoordinator__store
    request_digest = canonical_digest((DRAFT_SCHEMA, namespace, operation_id, field))

    def commit(db, metadata, epoch, now, owner, scope):
        from ..domains.d04.authored_lineage_v3 import AuthoredRootInputV3, compile_authored_root_candidate_v3
        _assembly, preset = _installation(c, authority)
        draft_key, head_key = character_draft_key(namespace), active_scheme_head_key(namespace)
        previous = _row(db, store, draft_key, optional=True)
        previous_head = _row(db, store, head_key, optional=True)
        if (previous is None) != (previous_head is None):
            raise ValueError("D12 current draft/head is only partly initialized")
        if previous is None:
            draft = CharacterDraft(namespace.persona_id, 1, {ROOT_FIELD: field}, {ROOT_FIELD: "owner"})
        else:
            raw = dict(previous[1]); raw.pop("schema")
            prior = CharacterDraft(**raw)
            head_raw = dict(previous_head[1]); head_raw.pop("schema")
            head = ActiveSchemeHeadV1(**head_raw)
            if (prior.scope != namespace.persona_id or prior.revision != previous[0]
                    or head.scope != namespace.persona_id or head.generation != previous_head[0]
                    or head.draft_ref != draft_key.token):
                raise ValueError("D12 current draft/head identity differs")
            if ROOT_FIELD in prior.fields:
                raise ValueError("authored root draft is already initialized")
            draft = CharacterDraft(namespace.persona_id, prior.revision + 1,
                {**prior.fields, ROOT_FIELD: field}, {**prior.field_sources, ROOT_FIELD: "owner"})
        candidate = compile_authored_root_candidate_v3(preset, AuthoredRootInputV3(
            field["candidate_id"], namespace.as_tuple, authority.actor,
            f"{draft_key.token}@{draft.revision}:{canonical_digest(draft)}",
            field["cursor"], field["preset_digest"], field["asset_digest"],
            _authored_root_blocks_v3(field)))
        owner_key = owner_grant_key(*namespace.as_tuple)
        owner_row = _row(db, store, owner_key)
        reads = [GraphVersion(draft_key, previous[0] if previous else 0),
                 GraphVersion(head_key, previous_head[0] if previous_head else 0),
                 GraphVersion(owner_key, owner_row[0])]
        writes = [GraphWrite(draft_key, {"schema": draft_key.type_name, **asdict(draft)})]
        head_revision = previous_head[0] if previous_head else 1
        if previous_head is None:
            head = ActiveSchemeHeadV1(namespace.persona_id, 1,
                canonical_digest(("initial_d12_head", namespace)), draft_key.token, 1,
                canonical_digest(draft), None, operation_id, "initial")
            writes.append(GraphWrite(head_key, {"schema": head_key.type_name, **asdict(head)}))
        graph_receipt = _commit_graph(c, db, metadata, epoch, now, operation_id,
            "d12.initial_d04_root_draft.v3", request_digest, reads, writes)
        return {"schema": DRAFT_SCHEMA, "operation_id": operation_id,
            "draft_ref": draft_key.token, "draft_revision": draft.revision,
            "draft_digest": canonical_digest(draft), "head_ref": head_key.token,
            "head_revision": head_revision, "candidate_digest": candidate.digest,
            "graph_receipt": graph_receipt}

    return c._owner_domain_write_v3(authority, lease, operation_id=operation_id,
        request_digest=request_digest, domains=("d04", "d12"),
        capability="workbench.create", commit=commit)


def allocate_current_d04_root_budget_v3(c, authority, lease, *, operation_id,
                                        parent_budget_lease_ref, ceiling):
    """Split a dedicated signed child from the installed root, exactly once."""
    _operation(operation_id)
    if type(parent_budget_lease_ref) is not str or not parent_budget_lease_ref:
        raise ValueError("installed parent budget lease required")
    if type(ceiling) is not dict or not ceiling or any(type(x) is not int or x <= 0 for x in ceiling.values()):
        raise ValueError("root allocation needs explicit positive integer ceilings")
    requested = _amounts(ceiling, allow_empty=False)
    _installation(c, authority)
    namespace = authority.namespace
    request_digest = canonical_digest((BUDGET_SCHEMA, namespace, operation_id,
                                        parent_budget_lease_ref, requested))
    child_id = "d04-root-budget-v3:" + canonical_digest((namespace, operation_id))[:48]

    def commit(db, metadata, epoch, now, owner, scope):
        assembly, _preset = _installation(c, authority)
        installed = assembly.installation_policy
        issuer = c._GraphCoordinator__d11_issuer
        if issuer is None or parent_budget_lease_ref != installed.root_lease.lease_id:
            raise ValueError("root allocation requires the installed D11 parent")
        parent = get_budget_lease(db, parent_budget_lease_ref)
        grant = issuer.current_budget_grant(db, parent_budget_lease_ref)
        if ((parent.bot_id, parent.persona_id) != namespace.as_tuple
                or parent.parent_id is not None or parent.state != "active"
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                or grant.lease_id != parent.lease_id or grant.currency != parent.currency
                or grant.grant_id != installed.root_grant.grant_id
                or grant.policy_ref != installed.root_grant.policy_ref
                or grant.valid_until_utc <= now
                or any(amount > grant.max_ceiling.get(name, 0) for name, amount in requested.items())):
            raise ValueError("current signed D11 parent does not cover root allocation")
        # A second first-use budget would make the installed resolver ambiguous.
        for (other_id,) in db.execute("SELECT DISTINCT lease_id FROM runtime_budget_grants WHERE status='active'").fetchall():
            other = issuer.current_budget_grant(db, other_id)
            if ((other.bot_id, other.persona_id) == namespace.as_tuple
                    and other.allowed_work_kinds == (ROOT_WORK_KIND_V3,)
                    and other.valid_until_utc > now and get_budget_lease(db, other_id).state == "active"):
                raise ValueError("a current dedicated D04 root budget already exists")
        child = BudgetLease(child_id, parent.lease_id, *namespace.as_tuple, parent.currency,
            requested, {}, {}, {}, 1, "active")
        receipt = create_budget_lease(db, child, "d04-root-allocate:" + operation_id, request_digest)
        child_grant = BudgetLeaseGrant("d04-root-grant-v3:" + canonical_digest((namespace, operation_id))[:48],
            1, *namespace.as_tuple, child_id, parent.currency, requested, (ROOT_WORK_KIND_V3,),
            grant.valid_until_utc, "d04-owner-root-allocation-v3")
        signature = issuer.issue_budget_grant(db, child_grant)
        if issuer.current_budget_grant(db, child_id) != child_grant:
            raise ValueError("dedicated root grant did not round trip")
        retained = get_budget_lease(db, parent.lease_id)
        if (retained.version != parent.version + 1 or retained.used != parent.used
                or retained.unconfirmed != parent.unconfirmed
                or any(retained.reserved.get(name, 0) != parent.reserved.get(name, 0) + amount
                       for name, amount in requested.items())):
            raise ValueError("D11 child allocation did not retain parent accounting")
        return {"schema": BUDGET_SCHEMA, "operation_id": operation_id, "lease_id": child_id,
            "parent_budget_lease_ref": parent.lease_id, "parent_version_before": parent.version,
            "parent_version_after": retained.version, "ceiling": requested,
            "grant_digest": canonical_digest(asdict(child_grant)), "grant_signature_digest": canonical_digest(signature),
            "creation_receipt": asdict(receipt)}

    return c._owner_domain_write_v3(authority, lease, operation_id=operation_id,
        request_digest=request_digest, domains=("d04", "d11", "d12"),
        capability="workbench.activate", commit=commit)


TOPOLOGY_TABLE = "graph_d04_root_topology_originals_v3"


def install_d04_root_topology_originals_v3(db):
    """The caller owns the transaction; topology history is immutable."""
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TOPOLOGY_TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        original_json TEXT NOT NULL, original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {TOPOLOGY_TABLE}_no_{action.lower()}
            BEFORE {action} ON {TOPOLOGY_TABLE}
            BEGIN SELECT RAISE(ABORT,'D04 authored topology original is immutable'); END""")


def _installed_topology_policy(package_root, manifest_digest, available_cpu_features=None):
    """Read explicit cross-block permission, not an inference from beta alone."""
    from pathlib import Path
    import hashlib
    from ..domains.d04.authored_topology_v3 import POLICY_PATH, POLICY_SCHEMA, TEMPLATE_PAIRS
    from ..host.installed_package import _safe_file, verify_installed_backend_runtime_v1
    from ..host.installed_d04_root_resources import load_installed_d04_root_preset_v3, _object
    root = Path(package_root)
    if root.is_symlink():
        raise ValueError("authored topology package is linked")
    root = root.resolve(strict=True)
    checked = verify_installed_backend_runtime_v1(root, manifest_digest,
        available_cpu_features=available_cpu_features)
    if not checked.verified or checked.manifest_digest != manifest_digest:
        raise ValueError("authored topology requires the pinned installed runtime")
    manifest_path = _safe_file(root, "release-manifest.json")
    policy_path = _safe_file(root, POLICY_PATH)
    operator_path = _safe_file(root, "resources/catalogue/d04-fixed-block-operator.json")
    if manifest_path is None or policy_path is None or operator_path is None:
        raise ValueError("installed authored topology assets are absent or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest:
        raise ValueError("authored topology installation manifest changed")
    manifest = _object(manifest_bytes, "authored topology manifest")
    content = policy_path.read_bytes()
    entries = [item for item in manifest.get("files", []) if item.get("path") == POLICY_PATH]
    if (len(entries) != 1 or entries[0].get("sha256") != hashlib.sha256(content).hexdigest()
            or entries[0].get("bytes") != len(content)):
        raise ValueError("authored topology policy is not manifest pinned")
    policy = _object(content, "authored topology policy")
    preset = load_installed_d04_root_preset_v3(root, manifest_digest,
        available_cpu_features=available_cpu_features)
    expected = {"schema": POLICY_SCHEMA, "topology_id": TOPOLOGY_ID,
        "policy_version": "3.0.0-alpha1",
        "calibration_status": "engineering_unvalidated_owner_selection_required",
        "root_preset_id": preset.preset_id, "root_preset_version": preset.preset_version,
        "root_preset_digest": preset.digest,
        "operator_path": "resources/catalogue/d04-fixed-block-operator.json",
        "operator_sha256": preset.assets.operator_sha256,
        "coefficient_parameter": "coupling_beta", "coefficient": 0.125,
        "axis_rule": "all_preset_axes_same_axis",
        "template_pairs": [list(pair) for pair in TEMPLATE_PAIRS], "edge_count": 48,
        "lineage": "owner_authored_configuration_not_d06_observation"}
    expected["content_digest"] = canonical_digest(expected)
    if policy != expected or canonical_serialize(policy).encode("utf-8") != content:
        raise ValueError("authored topology policy differs from registered exact topology")
    operator_bytes = operator_path.read_bytes()
    if hashlib.sha256(operator_bytes).hexdigest() != preset.assets.operator_sha256:
        raise ValueError("authored topology operator differs from root preset")
    operator = _object(operator_bytes, "authored topology operator")
    beta = [entry for entry in operator.get("parameter_bounds", [])
            if type(entry) is list and len(entry) == 3 and entry[0] == "coupling_beta"]
    if (beta != [["coupling_beta", 0.125, 0.125]]
            or operator.get("axis_ids") != list(preset.axes)
            or operator.get("operator_version") != preset.assets.operator_version
            or canonical_digest(operator.get("parameter_bounds")) != preset.assets.parameter_sha256):
        raise ValueError("authored topology has no exact installed singleton coefficient")
    return preset, policy


def _root_and_current_members(db, namespace, root_operation_id, issuer, preset):
    from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
    with d04_series_original_read_scope_v1(db):
        from ..domains.d04.authored_lineage_v3 import (
            decode_authored_root_candidate_v3, decode_authored_numeric_checkpoint_v2,
            decode_authored_feeling_state_v1, decode_authored_mood_state_v1,
            validate_authored_joint_predecessor_v3,
        )
        from .d04_root_original_store_v3 import read_d04_root_original_v3
        from .d11_d04_root_freeze_v3 import read_d11_root_freeze_v3
        from .joint_numeric_component import _authored_predecessor_original
        root = read_d04_root_original_v3(db, namespace=namespace, operation_id=root_operation_id)
        frozen = read_d11_root_freeze_v3(db, issuer, namespace=namespace, operation_id=root_operation_id)
        candidate = decode_authored_root_candidate_v3(json.loads(root.candidate_json))
        if (frozen is None or frozen.original_digest != root.signed_freeze_digest
                or frozen.freeze_read_digest != canonical_digest(json.loads(frozen.freeze_read_json))
                or candidate.preset != preset or candidate.namespace != namespace.as_tuple):
            raise ValueError("authored topology root signed original or installed preset differs")
        rows = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2') ORDER BY token",
            namespace.as_tuple).fetchall()
        if len(rows) != 3:
            raise ValueError("authored topology requires the complete three-member root")
        current, members = [], {}
        for ref, revision, encoded, valid in rows:
            key = AtomKey.from_token(ref)
            if key.type_name != "d04.numeric_checkpoint.v2" or revision < 1 or valid != 1:
                raise ValueError("authored topology member is absent, retired or unsupported")
            value = json.loads(encoded)
            if canonical_json(value) != encoded:
                raise ValueError("authored topology member bytes differ")
            checkpoint = decode_authored_numeric_checkpoint_v2(value)
            if key.name != checkpoint.block.block_id or checkpoint.namespace != namespace.as_tuple:
                raise ValueError("authored topology current member address differs")
            state_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (checkpoint.graph_state.ref,)).fetchone()
            if state_row is None or state_row[0] != revision or state_row[2] != 1:
                raise ValueError("authored topology current state is unavailable")
            state_value = json.loads(state_row[1])
            decode = decode_authored_feeling_state_v1 if checkpoint.block.kind == "feeling" else decode_authored_mood_state_v1
            state = decode(state_value)
            if canonical_json(state_value) != state_row[1] or state.root_operation_id != root_operation_id:
                raise ValueError("authored topology current state root differs")
            validate_authored_joint_predecessor_v3(checkpoint, state, revision)
            root_digest, _receipt_digest = _authored_predecessor_original(db, namespace, ref, revision, checkpoint, state)
            if root_digest != root.original_digest:
                raise ValueError("authored topology current members do not share one root")
            if checkpoint.block.template_id in members:
                raise ValueError("authored topology root repeats a template")
            members[checkpoint.block.template_id] = (ref, checkpoint)
            current.extend(((ref, revision, value, True),
                            (checkpoint.graph_state.ref, state_row[0], state_value, True)))
        templates = {item.template_id: item.kind for item in preset.block_templates}
        if set(members) != set(templates) or any(members[name][1].block.kind != kind for name, kind in templates.items()):
            raise ValueError("authored topology current templates differ from installed preset")
        return root, candidate, members, current


def _topology_edges(policy, preset, members, source_ref, effective_from, effective_until):
    from ..domains.d04.numeric_coupling import NumericCoupling, coupling_id, TEMPLATE, FACTOR_KIND
    from ..graph_types import Owner
    edges = []
    for left_template, right_template in policy["template_pairs"]:
        left_ref, right_ref = members[left_template][0], members[right_template][0]
        for axis in preset.axes:
            endpoints = sorted(((left_ref, axis), (right_ref, axis)))
            edge = NumericCoupling(coupling_id(*endpoints[0], *endpoints[1]), 1,
                preset.assets.scheme_version, *endpoints[0], *endpoints[1], TEMPLATE, FACTOR_KIND,
                policy["coefficient"], source_ref, effective_from, effective_until)
            owner = AtomKey.from_token(left_ref).owner
            key = AtomKey(Owner("persona", owner.bot, owner.persona), "d04.numeric_coupling.v1", edge.edge_id)
            edges.append((key.token, 1, json.loads(canonical_serialize(asdict(edge)))))
    edges.sort(key=lambda item: item[0])
    if len(edges) != 48 or len({item[0] for item in edges}) != 48:
        raise ValueError("registered authored topology requires exactly 48 unique undirected edges")
    return edges


def _graph_rows(db, refs):
    result = []
    for ref in sorted(set(refs)):
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
        if row is None:
            result.append((ref, 0, {}, False))
        else:
            value = json.loads(row[1])
            if canonical_json(value) != row[1]:
                raise ValueError("authored topology dependency bytes are not canonical")
            result.append((ref, row[0], value, bool(row[2])))
    return result


def _topology_owner_evidence(db, namespace, original, marker, writes, event):
    """Replay the retained W01 permit, CAS reads and original Owner grant.

    Historical authorization is checked against its original records. It is
    neither a new content permission nor a requirement to keep an old login
    alive. The caller still owns current execution/deletion/Owner admission.
    """
    from ..authority_service.v2_contract import FencePermitV2, from_wire
    from ..authority_service.v2_owner_contract import (
        OwnerGraphCommitProofV1, canonical_digest as owner_digest,
    )
    from ..graph_types import validate_owner_grant_v1
    from .restore_anchor import RestoreAnchor

    admission = original["owner_admission"]
    expected_fields = {"actor", "activation_generation", "grant_id", "grant_revision",
        "grant_digest", "authorization_head", "authorization_revision", "principal",
        "graph_incarnation", "request_digest", "permit_digest", "owner_session_binding_digest"}
    if (type(admission) is not dict or set(admission) != expected_fields
            or type(admission["actor"]) is not str or not admission["actor"]
            or admission["request_digest"] != original["request_digest"]):
        raise ValueError("authored topology historical Owner binding differs")
    request = canonical_digest((TOPOLOGY_SCHEMA, namespace, marker.operation_id,
                                marker.root_operation_id, float(marker.effective_until)))
    attempt = db.execute("SELECT request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,"
        "permit_json,receipt_json FROM graph_owner_domain_attempts_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, marker.operation_id)).fetchone()
    attempt_id = "owner-domain-" + canonical_digest((namespace, marker.operation_id, request))[:48]
    if (attempt is None or attempt[:2] != (request, attempt_id)
            or request != original["request_digest"] or attempt[5] is None or attempt[6] is None):
        raise ValueError("authored topology retained Owner attempt differs")
    permit = from_wire(json.loads(attempt[5]))
    anchor_raw = json.loads(attempt[2])
    anchor = RestoreAnchor(**anchor_raw)
    if (canonical_json(anchor_raw) != attempt[2]
            or type(permit) is not FencePermitV2 or permit.operation != "write"
            or permit.operation_id != attempt_id or permit.pinned_anchor != anchor
            or permit.generation != admission["activation_generation"]
            or canonical_digest(permit) != admission["permit_digest"]):
        raise ValueError("authored topology retained permit or anchor differs")
    metadata = GraphStore._decode_recovery(db.execute("SELECT schema,requirements_json,graph_revision "
        "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone(), namespace)
    if (metadata is None or metadata.requirements.authority_namespace != permit.namespace
            or metadata.requirements.authority_id != permit.authority_id):
        raise ValueError("authored topology historical permit namespace differs")
    receipt = json.loads(attempt[6])
    if (type(receipt) is not dict or receipt.get("original_digest") != canonical_digest(original)
            or receipt.get("marker_ref") != original["marker_ref"]
            or receipt.get("graph_receipt") != original["graph_receipt"]
            or receipt.get("operation_id") != marker.operation_id):
        raise ValueError("authored topology Owner admission original differs")

    prerequisites = original["prerequisite_rows"]
    if (type(prerequisites) is not list or len(prerequisites) != 10
            or any(type(item) is not list or len(item) != 4 or type(item[1]) is not int
                   or item[1] < 1 or item[3] is not True for item in prerequisites)
            or len({item[0] for item in prerequisites}) != len(prerequisites)):
        raise ValueError("authored topology original prerequisite set differs")
    expected_reads = sorted([[ref, revision] for ref, revision, _value, _valid in prerequisites]
                            + [[ref, 0] for ref, _revision, _value in writes])
    if (len({ref for ref, _revision in expected_reads}) != len(expected_reads)
            or json.loads(event[3]) != expected_reads
            or json.loads(event[4]) != [[*namespace.as_tuple, attempt[4]]]
            or json.loads(event[5]) != [] or event[2] != attempt[4] + 1):
        raise ValueError("authored topology original CAS read set or epoch differs")
    expected_keys = {active_scheme_head_key(namespace).token, character_draft_key(namespace).token,
        owner_grant_key(*namespace.as_tuple).token}
    from ..graph_types import Owner
    expected_keys.add(AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current").token)
    root_rows = json.loads(db.execute("SELECT original_json FROM graph_d04_root_originals_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, marker.root_operation_id)).fetchone()[0])
    expected_keys.update(row[0] for row in json.loads(root_rows["output_json"])["rows"])
    if {item[0] for item in prerequisites} != expected_keys:
        raise ValueError("authored topology original prerequisite coverage differs")
    for ref, revision, value, valid in prerequisites:
        key = AtomKey.from_token(ref)
        if (key.owner.bot, key.owner.persona) != namespace.as_tuple:
            raise ValueError("authored topology prerequisite crosses namespace")
        historical = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (ref, revision)).fetchone()
        if historical != (canonical_json(value), int(valid)):
            raise ValueError("authored topology prerequisite history differs")

    owner_row = next(item for item in prerequisites if item[0] == owner_grant_key(*namespace.as_tuple).token)
    grant = owner_row[2]
    validate_owner_grant_v1(grant)
    proof_row = db.execute("SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,"
        "graph_access_epoch,graph_epoch,graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if proof_row is None:
        raise ValueError("authored topology historical Owner issue proof is absent")
    proof = OwnerGraphCommitProofV1(namespace, *proof_row[:5], owner_row[1], *proof_row[5:8])
    if (proof_row[8] != canonical_json(asdict(proof))
            or owner_row[1] != 1 or grant["grant_revision"] != 1
            or grant["issue_operation_id"] != proof.operation_id
            or grant["scope"] != "/".join(namespace.as_tuple)
            or grant["authority_id"] != permit.authority_id
            or grant["graph_incarnation"] != proof.graph_incarnation
            or grant["principal"] != admission["principal"]
            or grant["grant_id"] != proof.grant_id or admission["grant_id"] != proof.grant_id
            or "sha256:" + canonical_digest(grant) != proof.grant_digest
            or admission["grant_digest"] != proof.grant_digest
            or admission["grant_revision"] != proof.grant_revision
            or admission["authorization_revision"] != 1
            or admission["authorization_head"] != owner_digest(proof)
            or "workbench.activate" not in grant["capabilities"]):
        raise ValueError("authored topology historical Owner grant/proof differs")
    return admission, permit, proof, grant


def adopt_current_d04_root_coupling_v3(c, authority, lease, *, operation_id,
                                       root_operation_id, effective_until):
    """Explicitly adopt the pinned 48-edge authored configuration, not events."""
    from ..domains.d04.authored_topology_v3 import AuthoredRootTopologyV3, TYPE_NAME, authored_topology_key_v3
    from ..graph_types import Owner
    _operation(operation_id); _operation(root_operation_id)
    if type(effective_until) not in (int, float) or not math.isfinite(effective_until):
        raise ValueError("authored topology requires an explicit finite interval end")
    effective_until = float(effective_until)
    _installation(c, authority)
    namespace, store = authority.namespace, c._GraphCoordinator__store
    request_digest = canonical_digest((TOPOLOGY_SCHEMA, namespace, operation_id, root_operation_id, effective_until))

    def commit(db, metadata, epoch, now, owner, scope):
        assembly, _ = _installation(c, authority)
        preset, policy = _installed_topology_policy(assembly.package_root,
            assembly.installation_policy.manifest_digest, assembly.available_cpu_features)
        install_d04_root_topology_originals_v3(db)
        root, candidate, members, member_rows = _root_and_current_members(
            db, namespace, root_operation_id, c._GraphCoordinator__d11_issuer, preset)
        if (any(row[1] != 1 for row in member_rows) or effective_until <= candidate.cursor):
            raise ValueError("authored topology must be adopted on the unadvanced root with a positive interval")
        existing = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN (?,?)", (*namespace.as_tuple, TYPE_NAME, "d04.numeric_coupling.v1")).fetchall()
        if existing:
            raise ValueError("authored root topology is already initialized or has foreign edges")
        marker_key = authored_topology_key_v3(namespace, operation_id)
        head_key, draft_key = active_scheme_head_key(namespace), character_draft_key(namespace)
        head_row = _row(db, store, head_key)
        raw_head = dict(head_row[1]); raw_head.pop("schema")
        head = ActiveSchemeHeadV1(**raw_head)
        draft_row = _row(db, store, draft_key)
        activation_key = AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current")
        activation_row = _row(db, store, activation_key)
        owner_key = owner_grant_key(*namespace.as_tuple)
        owner_row = _row(db, store, owner_key)
        if (head.adopted_operation_id != root_operation_id or head.generation != head_row[0]
                or head.draft_revision != draft_row[0] or head.draft_ref != draft_key.token
                or head.draft_digest != canonical_digest(CharacterDraft(**{k: v for k, v in draft_row[1].items() if k != "schema"}))):
            raise ValueError("authored topology requires the exact current root scheme/draft")
        edges = _topology_edges(policy, preset, members, marker_key.token, candidate.cursor, effective_until)
        admission = {"actor": authority.actor, "activation_generation": authority.activation_generation,
            "grant_id": owner.grant_id, "grant_revision": owner.grant_revision,
            "grant_digest": owner.grant_digest, "authorization_head": owner.authorization_head,
            "authorization_revision": owner.authorization_revision, "principal": asdict(owner.principal),
            "graph_incarnation": owner.graph_incarnation, "request_digest": request_digest,
            "permit_digest": canonical_digest(scope.permit),
            "owner_session_binding_digest": canonical_digest(c._GraphCoordinator__owner_session_proofs[lease])}
        marker = AuthoredRootTopologyV3(operation_id, root_operation_id, root.original_digest,
            root.signed_freeze_digest, assembly.installation_policy.manifest_digest,
            policy["content_digest"], preset.assets.operator_sha256, preset.digest,
            head_key.token, head_row[0], canonical_digest(head_row[1]), canonical_digest(admission),
            request_digest, tuple(sorted(ref for ref, _checkpoint in members.values())),
            canonical_digest(edges), policy["coefficient"], candidate.cursor, effective_until)
        marker_value = json.loads(canonical_serialize(asdict(marker)))
        write_rows = sorted(edges + [(marker_key.token, 1, marker_value)], key=lambda item: item[0])
        prerequisites = sorted(member_rows + [(head_key.token, head_row[0], head_row[1], True),
            (draft_key.token, draft_row[0], draft_row[1], True),
            (activation_key.token, activation_row[0], activation_row[1], True),
            (owner_key.token, owner_row[0], owner_row[1], True)], key=lambda item: item[0])
        reads = [GraphVersion(AtomKey.from_token(ref), revision) for ref, revision, _value, _valid in prerequisites]
        reads.extend(GraphVersion(AtomKey.from_token(ref), 0) for ref, _revision, _value in write_rows)
        receipt = _commit_graph(c, db, metadata, epoch, now, operation_id, TOPOLOGY_ACTIVITY,
            request_digest, reads, [GraphWrite(AtomKey.from_token(ref), value) for ref, _revision, value in write_rows])
        event = db.execute("SELECT digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*namespace.as_tuple, TOPOLOGY_ACTIVITY, operation_id)).fetchone()
        if event is None:
            raise ValueError("authored topology graph event absent")
        original = {"schema": TOPOLOGY_SCHEMA, "namespace": asdict(namespace), "operation_id": operation_id,
            "request_digest": request_digest, "installation_id": assembly.installation_policy.installation_id,
            "marker_ref": marker_key.token, "marker_value": marker_value,
            "root_operation_id": root_operation_id, "root_original_digest": root.original_digest,
            "root_freeze_digest": root.signed_freeze_digest, "policy": policy,
            "owner_admission": admission, "prerequisite_rows": prerequisites,
            "write_rows": write_rows, "event_digest": event[0], "graph_receipt": receipt}
        encoded, digest = canonical_serialize(original), canonical_digest(original)
        db.execute(f"INSERT INTO {TOPOLOGY_TABLE} VALUES(?,?,?,?,?)",
            (*namespace.as_tuple, operation_id, encoded, digest))
        return {"schema": TOPOLOGY_SCHEMA, "operation_id": operation_id, "root_operation_id": root_operation_id,
            "marker_ref": marker_key.token, "original_digest": digest, "edge_count": len(edges),
            "coefficient": marker.coefficient, "effective_from": marker.effective_from,
            "effective_until": marker.effective_until, "graph_receipt": receipt}

    return c._owner_domain_write_v3(authority, lease, operation_id=operation_id,
        request_digest=request_digest, domains=("d04", "d11", "d12"),
        capability="workbench.activate", commit=commit)


class InstalledD04AuthoredTopologyVerifierV3:
    """Concrete installation verifier usable by independent read-only Authority.

    Construct in trusted installation composition, never from request JSON.
    This verifies provenance only; it does not establish a current Owner fence.
    """
    def __init__(self, *, package_root, trusted_manifest_sha256, d11_issuer,
                 namespace, installation_id, available_cpu_features=None, historical_compatibility=None):
        from pathlib import Path
        from ..runtime_contracts import NamespaceId
        from .issuers import D11BudgetGrantIssuer
        if (type(namespace) is not NamespaceId or not isinstance(d11_issuer, D11BudgetGrantIssuer)
                or type(installation_id) is not str or not installation_id):
            raise TypeError("installed authored topology verifier facts are unavailable")
        self.package_root = Path(package_root)
        self.trusted_manifest_sha256, self.d11_issuer = trusted_manifest_sha256, d11_issuer
        self.namespace, self.installation_id = namespace, installation_id
        self.available_cpu_features = available_cpu_features
        if historical_compatibility is not None:
            from ..host.installed_d04_historical_compatibility_v1 import InstalledHistoricalD04CompatibilityV1
            if (type(historical_compatibility) is not InstalledHistoricalD04CompatibilityV1
                    or historical_compatibility.namespace != namespace
                    or historical_compatibility.installation_id != installation_id
                    or historical_compatibility.current_manifest_sha256 != trusted_manifest_sha256):
                raise ValueError("authored topology historical resource qualification differs")
            historical_compatibility.require_current_selection_v1()
        self._historical_compatibility = historical_compatibility
        # One verifier is scoped to one operation. A parsed admission DTO is
        # never an input: only this actual paired read may bind its location.
        self._location_observation = None
        self._numeric_location_bridge = None

    def observe_current_location_for_fence_v3(self, port, scope):
        """Use as the pre/post SQL fence observer; performs the real paired RPC."""
        from ..host.v2_fence_port import V2FencePort
        from ..runtime_contracts import FenceScope
        from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
        if (type(port) is not V2FencePort or type(scope) is not FenceScope
                or scope.namespace != self.namespace or scope.operation not in {"read", "write"}
                or port.installation_grant.installation_id != self.installation_id
                or port.installation_grant.manifest_digest != self.trusted_manifest_sha256):
            raise ValueError("authored topology requires its actual installed location port/fence")
        self._location_observation = None
        self._numeric_location_bridge = None
        observed, permit = port.get_current_background_owner_authority_for_fence_v1(
            namespace=scope.namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
        if (type(observed) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit
                or observed.guard.namespace != self.namespace
                or observed.guard.authority_id != permit.authority_id
                or observed.guard.pending_revoke_operation_id is not None
                or observed.guard.minimum_revocation_revision or observed.guard.minimum_revocation_epoch):
            raise ValueError("authored topology current location authority differs")
        self._location_observation = (scope, observed)
        if self._historical_compatibility is not None:
            self._historical_compatibility.observe_current_process_v1()
        return observed

    def observe_current_numeric_bridge_v3(self, port, bridge, scope):
        """Bind actual paired numeric two-head authority; do not rewrite a permit."""
        from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
        from ..authority_service.d04_numeric_claim_bridge_v3 import D04NumericAdoptionBridgeV3
        from ..runtime_contracts import FenceScope
        if (type(port) is not InstalledC04AuthorityPortV3 or type(bridge) is not D04NumericAdoptionBridgeV3
                or type(scope) is not FenceScope or scope.permit != bridge.permit
                or scope.pinned_anchor != bridge.after_anchor or scope.namespace != self.namespace
                or port._grant.installation_id != self.installation_id
                or port._grant.manifest_digest != self.trusted_manifest_sha256):
            raise ValueError("authored topology numeric bridge needs the actual installed port")
        observed = port.numeric_validate_gate(bridge.binding, bridge)
        if observed != bridge:
            raise ValueError("authored topology numeric bridge original changed")
        self._location_observation = (scope, observed.owner_authority)
        self._numeric_location_bridge = observed
        if self._historical_compatibility is not None:
            self._historical_compatibility.observe_current_process_v1()
        return observed.owner_authority

    def observe_current_service_location_for_fence_v3(self, service, scope, *, credential, subject):
        """Same independent read for an installed Authority-local composition.

        Call before entering a Graph transaction or any caller-owned Core
        transaction; the concrete target service owns its normal frozen read.
        """
        from ..authority_service.d12_target_owner_admission_v1 import (
            InstalledD12TargetOwnerAdmissionServiceV1, D12CurrentOwnerAuthorityV1,
        )
        from ..authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from ..runtime_contracts import FenceScope
        if (type(service) not in {InstalledD12TargetOwnerAdmissionServiceV1, InstalledD12OwnerStorageAdmissionServiceV1}
                or type(scope) is not FenceScope or scope.namespace != self.namespace
                or service.namespace_id != self.namespace or service.installation_id != self.installation_id
                or service.core._db.in_transaction):
            raise ValueError("authored topology requires its concrete current target service")
        self._location_observation = None
        self._numeric_location_bridge = None
        observed, permit = service.get_current_background_owner_authority_for_fence_v1(
            credential=credential, subject=subject, permit=scope.permit)
        if (type(observed) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit
                or observed.guard.namespace != self.namespace
                or type(service) is InstalledD12TargetOwnerAdmissionServiceV1 and observed.target_admission is None
                or observed.guard.pending_revoke_operation_id is not None
                or observed.guard.minimum_revocation_revision or observed.guard.minimum_revocation_epoch):
            raise ValueError("authored topology concrete target authority differs")
        self._location_observation = (scope, observed)
        if self._historical_compatibility is not None:
            self._historical_compatibility.observe_current_process_v1()
        return observed

    def _require_current_location(self, db, namespace, original, admission, historical_permit, proof, grant):
        """Compare actual target admission against this transaction's location.

        Source provenance stays byte-identical. Imported receipts alone, a
        configured target ID, or a caller-created admission cannot relocate it.
        """
        original_installation = original["installation_id"]
        if original_installation == self.installation_id:
            metadata = GraphStore._decode_recovery(db.execute("SELECT schema,requirements_json,graph_revision "
                "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone(), namespace)
            if metadata is None:
                raise ValueError("authored topology current source location is absent")
            if metadata.requirements.graph_incarnation != proof.graph_incarnation:
                if self._location_observation is None:
                    raise ValueError("authored topology C09 source needs actual current storage admission")
                scope, observed = self._location_observation
                anchor = scope.pinned_anchor
                bridge = self._numeric_location_bridge
                if bridge is not None:
                    if (bridge.permit != scope.permit or bridge.after_anchor != scope.pinned_anchor
                            or bridge.owner_authority != observed or bridge.before_graph_revision != metadata.graph_revision
                            or bridge.before_requirements_json != canonical_serialize(asdict(metadata.requirements))):
                        raise ValueError("authored topology source numeric before/after closure differs")
                    anchor = bridge.before_anchor
                from .d04_owner_storage_binding_v1 import require_d04_source_storage_binding_v1
                require_d04_source_storage_binding_v1(db, namespace=namespace, metadata=metadata,
                    scope=scope, observed=observed, installation_id=self.installation_id, business_anchor=anchor)
            return
        from .graph_migration_snapshot_v1 import _read_import_receipt_locked
        observation = self._location_observation
        if observation is None:
            raise ValueError("authored topology migrated source needs current independent target admission")
        scope, observed = observation
        target = observed.target_admission
        metadata = GraphStore._decode_recovery(db.execute("SELECT schema,requirements_json,graph_revision "
            "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone(), namespace)
        if target is None or metadata is None:
            raise ValueError("authored topology current target location proof is absent")
        requirements = metadata.requirements
        imported = _read_import_receipt_locked(db, namespace, target.transfer_id)
        current_grant = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*namespace.as_tuple).token,)).fetchone()
        current_epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone()
        if (scope.namespace != namespace or scope.authority_namespace != requirements.authority_namespace
                or scope.permit.pinned_anchor != scope.pinned_anchor
                or scope.permit.authority_id != requirements.authority_id
                or scope.permit.generation != requirements.activation_generation
                or scope.permit.namespace != requirements.authority_namespace
                or scope.graph_revision != metadata.graph_revision
                or current_epoch != (scope.graph_epoch.revision,)
                or target.source_installation_id != original_installation
                or target.target_installation_id != self.installation_id
                or target.namespace != namespace or target.authority_namespace != requirements.authority_namespace
                or target.target_holder != scope.permit.holder
                or target.activation_generation != requirements.activation_generation
                or target.revocation_epoch != requirements.revocation_epoch
                or target.graph_incarnation != requirements.graph_incarnation
                or observed.guard != target.source_owner_guard
                or target.source_owner_guard.authorization_head != admission["authorization_head"]
                or target.source_grant_ref != owner_grant_key(*namespace.as_tuple).token
                or target.source_grant_revision != proof.grant_revision
                or target.source_grant_digest != proof.grant_digest
                or asdict(target.principal) != grant["principal"]
                or current_grant != (proof.grant_revision, canonical_json(grant), 1)
                or imported is None or imported.graph_commit_digest != target.target_import_digest
                or imported.snapshot_digest != target.source_snapshot_digest
                or imported.source_graph_incarnation != admission["graph_incarnation"]
                or imported.target_activation_generation != target.activation_generation
                or historical_permit.generation >= target.activation_generation):
            raise ValueError("authored topology migrated original/current target bindings differ")
        anchor = scope.pinned_anchor
        bridge = self._numeric_location_bridge
        if bridge is not None:
            if (bridge.permit != scope.permit or bridge.after_anchor != scope.pinned_anchor
                    or bridge.owner_authority != observed or bridge.before_graph_revision != metadata.graph_revision
                    or bridge.before_requirements_json != canonical_serialize(asdict(requirements))):
                raise ValueError("authored topology numeric before/after closure differs")
            anchor = bridge.before_anchor
        if (requirements.authority_id != anchor.authority_id
                or requirements.activation_generation != anchor.activation_generation
                or requirements.revocation_epoch != anchor.revocation_epoch
                or tuple(getattr(requirements, field) for field in (
                    "deletion_journal_id", "deletion_seq", "deletion_digest",
                    "execution_journal_id", "execution_seq", "execution_digest"))
                   != tuple(getattr(anchor, field) for field in (
                    "deletion_journal_id", "deletion_seq", "deletion_digest",
                    "execution_journal_id", "execution_seq", "execution_digest"))
                or target.storage_continuation_ref is None and imported.target_graph_incarnation != requirements.graph_incarnation
                or metadata.graph_revision < imported.target_graph_revision):
            raise ValueError("authored topology target fence or storage continuation changed")

    def verify_in_transaction(self, db, namespace, edge):
        import sqlite3
        from ..domains.d04.authored_topology_v3 import (
            TYPE_NAME, decode_authored_root_topology_v3, authored_topology_key_v3,
        )
        from ..domains.d04.numeric_coupling import NumericCoupling
        if (type(db) is not sqlite3.Connection or not db.in_transaction or namespace != self.namespace
                or type(edge) is not NumericCoupling):
            raise ValueError("authored topology verification requires its pinned namespace transaction")
        source_key = AtomKey.from_token(edge.source_ref)
        if (source_key.type_name != TYPE_NAME or source_key.owner.kind != "persona"
                or (source_key.owner.bot, source_key.owner.persona) != namespace.as_tuple
                or any(AtomKey.from_token(ref).type_name != "d04.numeric_checkpoint.v2"
                       for ref in (edge.left_ref, edge.right_ref))):
            raise ValueError("authored topology source or endpoint lineage differs")
        preset, policy = _installed_topology_policy(self.package_root,
            self.trusted_manifest_sha256, self.available_cpu_features)
        row = db.execute(f"SELECT original_json,original_digest FROM {TOPOLOGY_TABLE} "
            "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, source_key.name)).fetchone()
        if row is None:
            raise ValueError("authored topology immutable original is absent")
        original = json.loads(row[0])
        expected_fields = {"schema", "namespace", "operation_id", "request_digest", "installation_id",
            "marker_ref", "marker_value", "root_operation_id", "root_original_digest", "root_freeze_digest",
            "policy", "owner_admission", "prerequisite_rows", "write_rows", "event_digest", "graph_receipt"}
        if (type(original) is not dict or set(original) != expected_fields
                or canonical_serialize(original) != row[0] or canonical_digest(original) != row[1]
                or original.get("schema") != TOPOLOGY_SCHEMA or original.get("namespace") != asdict(namespace)
                or original.get("operation_id") != source_key.name or original.get("marker_ref") != source_key.token
                or type(original.get("installation_id")) is not str or not original["installation_id"]
                or original.get("policy") != policy):
            raise ValueError("authored topology immutable original identity differs")
        marker = decode_authored_root_topology_v3(original["marker_value"])
        if marker.manifest_digest != self.trusted_manifest_sha256:
            if self._historical_compatibility is None:
                raise ValueError("authored topology historical package is not independently registered")
            self._historical_compatibility.require_original_manifest_v1(marker.manifest_digest)
        if (authored_topology_key_v3(namespace, marker.operation_id) != source_key
                or marker.preset_digest != preset.digest or marker.policy_digest != policy["content_digest"]
                or marker.operator_sha256 != preset.assets.operator_sha256
                or marker.owner_binding_digest != canonical_digest(original["owner_admission"])
                or marker.request_digest != original["request_digest"]
                or marker.root_operation_id != original["root_operation_id"]):
            raise ValueError("authored topology marker differs from its original")
        root, candidate, members, member_rows = _root_and_current_members(db, namespace,
            marker.root_operation_id, self.d11_issuer, preset)
        if (root.original_digest != marker.root_original_digest or root.signed_freeze_digest != marker.root_freeze_digest
                or root.original_digest != original["root_original_digest"]
                or root.signed_freeze_digest != original["root_freeze_digest"]
                or marker.member_refs != tuple(sorted(ref for ref, _checkpoint in members.values()))
                or marker.coefficient != policy["coefficient"] or marker.effective_from != candidate.cursor):
            raise ValueError("authored topology common root or interval changed")
        edges = _topology_edges(policy, preset, members, source_key.token, marker.effective_from, marker.effective_until)
        writes = sorted(edges + [(source_key.token, 1, original["marker_value"])], key=lambda item: item[0])
        if (canonical_digest(edges) != marker.edge_write_set_digest
                or json.loads(canonical_serialize(writes)) != original["write_rows"]
                or not any(value == json.loads(canonical_serialize(asdict(edge))) for _ref, _rev, value in edges)):
            raise ValueError("authored topology exact edge original differs")
        event = db.execute("SELECT digest,revisions,epoch_revision,reads,epoch_reads,invalidated FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*namespace.as_tuple, TOPOLOGY_ACTIVITY, marker.operation_id)).fetchone()
        receipt = original["graph_receipt"]
        if (event is None or event[0] != original["event_digest"]
                or json.loads(event[1]) != [[ref, rev] for ref, rev, _value in writes]
                or receipt != {"status": "committed", "revisions": json.loads(event[1]), "invalidated": [],
                    "epoch": {"bot": namespace.bot_id, "persona": namespace.persona_id, "revision": event[2]}}):
            raise ValueError("authored topology exact graph event/receipt differs")
        for ref, revision, value in writes:
            historical = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
                "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
                (ref, revision, *namespace.as_tuple, TOPOLOGY_ACTIVITY, marker.operation_id)).fetchone()
            if historical != (canonical_json(value), 1):
                raise ValueError("authored topology graph history differs")
        admission, historical_permit, owner_proof, owner_grant = _topology_owner_evidence(
            db, namespace, original, marker, writes, event)
        self._require_current_location(db, namespace, original, admission, historical_permit,
            owner_proof, owner_grant)
        current_refs = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN (?,?) ORDER BY token", (*namespace.as_tuple, TYPE_NAME, "d04.numeric_coupling.v1")).fetchall()
        if tuple(ref for (ref,) in current_refs) != tuple(ref for ref, _rev, _value in writes):
            raise ValueError("authored topology current complete edge/marker inventory differs")
        current = _graph_rows(db, (ref for ref, _rev, _value in writes))
        if any((ref, revision, value, valid) != (expected[0], expected[1], expected[2], True)
               for (ref, revision, value, valid), expected in zip(current, writes)):
            raise ValueError("authored topology current marker or edge was changed/retired")
        # Only the adopted head and role are current execution dependencies.
        # Editing an unadopted draft must not suspend the active configuration;
        # its exact historical value was independently replayed above.
        stable = [item for item in original["prerequisite_rows"]
            if AtomKey.from_token(item[0]).type_name in {
                "d12.active_scheme_head.v1", "d01.persona_activation.v1"}]
        if len(stable) != 2:
            raise ValueError("authored topology original omitted configuration prerequisites")
        stable_current = _graph_rows(db, (item[0] for item in stable))
        if json.loads(canonical_serialize(stable_current)) != stable:
            raise ValueError("authored topology active scheme or role changed")
        head = next(item for item in stable_current if item[0] == marker.active_scheme_ref)
        if head[1] != marker.active_scheme_revision or canonical_digest(head[2]) != marker.active_scheme_digest:
            raise ValueError("authored topology active scheme commitment differs")
        return tuple(sorted(current + member_rows + stable_current, key=lambda item: item[0]))


def verifier_for_coordinator_v3(c):
    from ..graph_coordinator import GraphCoordinator
    if type(c) is not GraphCoordinator:
        raise TypeError("installed Graph coordinator required")
    assembly = c._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise ValueError("installed authored topology assembly absent")
    policy = assembly.installation_policy
    return InstalledD04AuthoredTopologyVerifierV3(package_root=assembly.package_root,
        trusted_manifest_sha256=policy.manifest_digest, d11_issuer=c._GraphCoordinator__d11_issuer,
        namespace=policy.namespace, installation_id=policy.installation_id,
        available_cpu_features=assembly.available_cpu_features,
        historical_compatibility=getattr(c, "_GraphCoordinator__d04_historical_compatibility_v1", None))
