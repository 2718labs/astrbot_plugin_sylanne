"""Explicit Owner selection and signed, immutable D04 semantic installation.

The package's role-neutral engineering template never self-authorizes. W01
checks the signed Owner session, current role, all actual root descendants and
Authority write fence before signing an original in the same business DB.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from uuid import UUID

from ..contracts import StaleRead
from ..domains.d04.authored_lineage_v3 import (
    decode_authored_numeric_checkpoint_v2, decode_authored_feeling_state_v1,
    decode_authored_mood_state_v1, decode_authored_root_candidate_v3,
    validate_authored_joint_predecessor_v3,
)
from ..graph_types import AtomKey
from ..runtime_contracts import AuthorityContext, FenceScope, canonical_digest, canonical_serialize
from .d04_root_original_store_v3 import read_d04_root_original_v3
from .d11_d04_root_freeze_v3 import read_d11_root_freeze_v3
from .joint_numeric_component import _authored_predecessor_original, MAX_ROWS
from .d04_semantic_mapping_v3 import InstalledD04SemanticMappingV3

TABLE = "graph_d04_semantic_installations_v3"
SIGN_KIND = "d11.owner-selected-d04-semantic-installation.v3"


def install_d04_semantic_installation_schema_v3(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
        operation_id TEXT NOT NULL, original_json TEXT NOT NULL,
        original_digest TEXT NOT NULL, signature TEXT NOT NULL,
        PRIMARY KEY(bot,persona,revision), UNIQUE(bot,persona,operation_id))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {TABLE}_no_{action.lower()}
            BEFORE {action} ON {TABLE}
            BEGIN SELECT RAISE(ABORT,'D04 semantic installation original is immutable'); END""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d04_owner_install_attempts_v3 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
        graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
        permit_json TEXT, finished INTEGER NOT NULL DEFAULT 0, result_json TEXT,
        PRIMARY KEY(bot,persona,operation_id))""")
    from .d11_role_clock_installation_v1 import install_d11_role_clock_schema_v1
    install_d11_role_clock_schema_v1(db)


def _operation(value):
    try:
        parsed = UUID(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("D04 Owner operation_id must be canonical UUID4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("D04 Owner operation_id must be canonical UUID4")


def _read_signed(db, issuer, table, kind, namespace, *, operation_id=None):
    if not db.in_transaction:
        raise ValueError("D04 signed installation original requires a pinned transaction")
    suffix = " AND operation_id=?" if operation_id is not None else " ORDER BY revision DESC LIMIT 1"
    args = (*namespace.as_tuple, operation_id) if operation_id is not None else namespace.as_tuple
    row = db.execute(f"SELECT revision,operation_id,original_json,original_digest,signature FROM {table} "
        "WHERE bot=? AND persona=?" + suffix, args).fetchone()
    if row is None:
        return None
    revision, operation, encoded, digest, signature = row
    issuer._signer.verify(kind, encoded, signature)
    original = json.loads(encoded)
    if (canonical_serialize(original) != encoded or canonical_digest(original) != digest
            or original["namespace"] != asdict(namespace) or original["revision"] != revision
            or original["operation_id"] != operation):
        raise ValueError("D04 signed installation original identity or content differs")
    return original, digest


def _insert_signed(db, issuer, table, kind, namespace, body):
    encoded, digest = canonical_serialize(body), canonical_digest(body)
    db.execute(f"INSERT INTO {table} VALUES(?,?,?,?,?,?,?)", (*namespace.as_tuple,
        body["revision"], body["operation_id"], encoded, digest, issuer._signer.sign(kind, encoded)))
    return body, digest


def _current_inputs(reader, db, namespace):
    """Read complete current members and replay each actual committed lineage."""
    from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
    with d04_series_original_read_scope_v1(db):
        scope, guard, profile = reader._current(db, namespace)
        graph = reader.graph
        role, _bindings, epoch, _versions = graph._scene_binding_state_locked(namespace, guard)
        if role.namespace != namespace or role.graph_epoch != epoch.revision:
            raise ValueError("D04 current role epoch differs")
        role_rows = []
        for version in sorted(role.read_versions, key=lambda v: v.key.token):
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (version.key.token,)).fetchone()
            if row is None or row[0] != version.revision or row[2] != 1:
                raise ValueError("D04 current role graph original changed")
            role_rows.append((version.key.token, row[0], json.loads(row[1]), True))
        rows = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2') ORDER BY token",
            namespace.as_tuple).fetchall()
        if not rows or len(rows) > MAX_ROWS:
            raise ValueError("D04 complete current numeric component is absent or too large")
        members, roots, cursors, shares = [], {}, [], []
        templates = dict(profile.raw["template_shares"])
        used_templates = set()
        for ref, revision, encoded, valid in rows:
            key = AtomKey.from_token(ref)
            if (not valid or revision < 1 or key.type_name != "d04.numeric_checkpoint.v2"
                    or key.owner.kind != "persona" or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
                raise ValueError("D04 current component contains invalid or unsupported members")
            checkpoint = decode_authored_numeric_checkpoint_v2(json.loads(encoded))
            if checkpoint.namespace != namespace.as_tuple or key.name != checkpoint.block.block_id:
                raise ValueError("D04 current checkpoint namespace or block identity differs")
            state_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (checkpoint.graph_state.ref,)).fetchone()
            if state_row is None or state_row[0] != revision or state_row[2] != 1:
                raise ValueError("D04 current component state is incomplete")
            decode = decode_authored_feeling_state_v1 if checkpoint.block.kind == "feeling" else decode_authored_mood_state_v1
            state = decode(json.loads(state_row[1]))
            validate_authored_joint_predecessor_v3(checkpoint, state, revision)
            root = roots.get(state.root_operation_id)
            if root is None:
                root = read_d04_root_original_v3(db, namespace=namespace, operation_id=state.root_operation_id)
                frozen = read_d11_root_freeze_v3(db, graph._GraphCoordinator__d11_issuer,
                    namespace=namespace, operation_id=root.operation_id)
                if frozen is None or frozen.original_digest != root.signed_freeze_digest:
                    raise ValueError("D04 root lacks its independently signed D11 original")
                candidate = decode_authored_root_candidate_v3(json.loads(root.candidate_json))
                if (candidate.preset.preset_id != profile.raw["root_preset_id"]
                        or candidate.preset.preset_version != profile.raw["root_preset_version"]
                        or candidate.preset.digest != profile.raw["root_preset_digest"]):
                    raise ValueError("D04 root preset is outside installed semantic profile")
                roots[root.operation_id] = root
            root_digest, _receipt_digest = _authored_predecessor_original(db, namespace, ref, revision, checkpoint, state)
            if root_digest != root.original_digest:
                raise ValueError("D04 current component root provenance differs")
            template = checkpoint.block.template_id
            if template not in templates or template in used_templates:
                raise ValueError("D04 profile must explicitly cover each unique actual block template")
            used_templates.add(template)
            members.append((ref, checkpoint.block.block_id, checkpoint.block.facet_id, checkpoint.block.kind,
                template, checkpoint.root_candidate_digest, root.operation_id, root.original_digest))
            shares.append((ref, templates[template]))
            cursors.append(checkpoint.cursor)
        if len(roots) != 1 or used_templates != set(templates) or len(set(cursors)) != 1:
            raise ValueError("D04 semantic profile requires exact complete synchronized root component coverage")
        return {"guard": guard, "profile": profile, "role": role,
            "role_rows": role_rows, "member_bindings": members, "block_shares": shares,
            "cursor": cursors[0], "role_ref": role.head_id,
            "persona_version": str(role.plan.version), "scope": scope}


def _installation_ref(reader, namespace):
    grant = reader.graph._GraphCoordinator__content_fence_v2.installation_grant
    return "d04-semantic-installation:" + canonical_digest((namespace, grant.installation_id, reader.manifest_sha256))


def _current_matches(original, inputs, reader, namespace):
    # Binary64 values are in canonical signed JSON. All accepted shares are
    # explicitly dyadic in this registered profile, so no rounding fallback.
    expected = {
        "installation_ref": reader.qualified_original_installation_ref(
            reader.graph._GraphCoordinator__store._db, namespace, original),
        "manifest_sha256": reader.qualified_original_manifest_sha256(
            reader.graph._GraphCoordinator__store._db, namespace, original),
        "profile_json": inputs["profile"].profile_json,
        "profile_digest": inputs["profile"].profile_digest,
        "owner_guard": asdict(inputs["guard"]),
        "role_rows": inputs["role_rows"],
        "member_bindings": inputs["member_bindings"],
    }
    if any(canonical_serialize(original.get(k)) != canonical_serialize(v) for k, v in expected.items()):
        raise ValueError("D04 semantic Owner, role, installed profile or component changed")


def read_current_semantic_mapping_v3(reader, db, namespace):
    inputs = _current_inputs(reader, db, namespace)
    saved = _read_signed(db, reader.graph._GraphCoordinator__d11_issuer, TABLE, SIGN_KIND, namespace)
    if saved is None:
        raise ValueError("D04 semantic profile requires explicit current Owner acceptance")
    original, digest = saved
    if original.get("schema") != "d04.owner-semantic-installation-original.v3" or original.get("state") != "active":
        raise ValueError("D04 semantic profile acceptance is absent or revoked")
    _current_matches(original, inputs, reader, namespace)
    asset = inputs["profile"].bind(role_ref=inputs["role_ref"], persona_version=inputs["persona_version"])
    raw = inputs["profile"].raw
    if (canonical_serialize(original["bound_asset"]) != canonical_serialize(asdict(asset))
            or canonical_serialize(original["block_shares"]) != canonical_serialize(inputs["block_shares"])):
        raise ValueError("D04 accepted semantic mapping or explicit shares differ")
    return InstalledD04SemanticMappingV3(asset, original["installation_ref"],
        "d04-semantic-acceptance:" + original["operation_id"], original["revision"], digest,
        raw["allocation_policy_id"], raw["allocation_policy_version"],
        tuple(tuple(row) for row in inputs["block_shares"]))


def _owner_write(reader, authority, lease, *, operation_id, request, commit):
    """Shared installed Owner operation. No caller callback is an API field."""
    _operation(operation_id)
    graph = reader.graph
    if (type(authority) is not AuthorityContext or authority.issuer_domain != "d12"
            or "persona" not in authority.owner_scope
            or getattr(graph, "_GraphCoordinator__d04_semantic_mapping_reader", None) is not reader):
        raise ValueError("D04 Owner operation requires the registered installed reader")
    graph._authorize(lease, authority, frozenset(("d04", "d11", "d12")), owner_read=True)
    binding = graph._GraphCoordinator__owner_leases.get(lease)
    proof = graph._GraphCoordinator__owner_session_proofs.get(lease)
    if (binding is None or proof is None or "workbench.activate" not in binding.capabilities
            or binding.actor != authority.actor or binding.namespace != authority.namespace
            or binding.purpose != authority.purpose or authority.audience != (binding.audience,)):
        raise ValueError("D04 Owner operation lacks its current signed session and activation capability")
    store, port, namespace = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2, authority.namespace
    grant = port.installation_grant
    if grant.manifest_digest != reader.manifest_sha256:
        raise ValueError("D04 semantic installation differs from actual installed grant")
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
    target = metadata.requirements
    if target.activation_generation != authority.activation_generation:
        raise StaleRead("D04 Owner activation changed")
    anchor = port.current_anchor(namespace=namespace, authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target, anchor):
        raise StaleRead("D04 Owner installation graph/Authority anchor differs")
    from .first_ingress_v2 import trusted_upper
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    request_digest = canonical_digest((namespace, operation_id, authority.actor, request))
    from uuid import uuid4
    from ..authority_service.v2_contract import from_wire, to_wire
    from .restore_anchor import RestoreAnchor
    attempt_table = "graph_d04_owner_install_attempts_v3"
    with store._lock:
        saved = store._db.execute(f"SELECT request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,"
            f"permit_json,finished,result_json FROM {attempt_table} WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, operation_id)).fetchone()
    if saved is not None and saved[0] != request_digest:
        raise ValueError("D04 Owner operation ID reused with different immutable request")
    if saved is not None and saved[5] is not None and not saved[6]:
        actual, state = port.get_fence_operation(namespace=namespace,
            authority_namespace=target.authority_namespace, operation_id=saved[1])
        if actual != from_wire(json.loads(saved[5])) or state not in {"active", "finished"}:
            raise ValueError("D04 Owner original fence is unavailable")
        if state == "active" and saved[7] is not None:
            from ..graph_types import NamespaceEpoch
            replay_scope = FenceScope(namespace, target.authority_namespace, authority.activation_generation,
                "write", saved[1], actual, actual.pinned_anchor,
                NamespaceEpoch(*namespace.as_tuple, saved[4]), saved[3])
            port.finish_fence(replay_scope, request_id="finish:" + saved[1],
                request_digest="sha256:" + canonical_digest((saved[1], actual.token, request_digest)))
            state = "finished"
        if state == "finished":
            with store._lock:
                store._db.execute(f"UPDATE {attempt_table} SET finished=1 WHERE bot=? AND persona=? AND operation_id=? AND attempt_id=?",
                    (*namespace.as_tuple, operation_id, saved[1]))
            saved = (*saved[:6], 1, saved[7])
    if saved is None or saved[6]:
        attempt = "d04-owner-install:" + str(uuid4())
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("D04 graph changed before durable Owner installation intent")
                values = (request_digest, attempt, canonical_serialize(asdict(anchor)), metadata.graph_revision, epoch.revision)
                if saved is None:
                    db.execute(f"INSERT INTO {attempt_table} VALUES(?,?,?,?,?,?,?,?,NULL,0,NULL)",
                        (*namespace.as_tuple, operation_id, *values))
                else:
                    db.execute(f"UPDATE {attempt_table} SET request_digest=?,attempt_id=?,anchor_json=?,graph_revision=?,"
                        "graph_epoch=?,permit_json=NULL,finished=0,result_json=NULL WHERE bot=? AND persona=? AND operation_id=? "
                        "AND attempt_id=? AND request_digest=? AND finished=1",
                        (*values, *namespace.as_tuple, operation_id, saved[1], request_digest))
                    if db.execute("SELECT changes()").fetchone() != (1,):
                        raise StaleRead("D04 Owner installation attempt changed before replay")
                db.commit()
            except BaseException:
                db.rollback()
                raise
        saved = (*values, None, 0, None)
    elif (RestoreAnchor(**json.loads(saved[2])) != anchor
            or saved[3:5] != (metadata.graph_revision, epoch.revision)):
        raise StaleRead("D04 unresolved Owner installation must retain its original graph and Authority fence")
    attempt = saved[1]
    if saved[5] is not None:
        permit = from_wire(json.loads(saved[5]))
    else:
        # Same persisted attempt recovers begin-ack loss without starting a
        # second independent operation or weakening the original snapshot.
        permit = port.begin_fence(namespace=namespace, authority_namespace=target.authority_namespace,
            holder=graph._GraphCoordinator__holder, generation=authority.activation_generation,
            operation="write", operation_id=attempt, expected_anchor=anchor, retain_on_unknown=True)
        with store._lock:
            store._db.execute(f"UPDATE {attempt_table} SET permit_json=? WHERE bot=? AND persona=? AND operation_id=? "
                "AND attempt_id=? AND permit_json IS NULL",
                (canonical_serialize(to_wire(permit)), *namespace.as_tuple, operation_id, attempt))
            if store._db.execute("SELECT changes()").fetchone() != (1,):
                raise StaleRead("D04 Owner original permit changed before journal retention")
    scope = FenceScope(namespace, target.authority_namespace, authority.activation_generation,
        "write", attempt, permit, anchor, epoch, metadata.graph_revision)
    try:
        graph._owner_binding_in_fence(authority, scope, binding.principal, binding, owner_session_proof=proof)
        with reader.current_owner_selection_fence(scope, authority, lease):
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("D04 Owner graph changed before installation")
                    inputs = _current_inputs(reader, db, namespace)
                    # Session tokens are never saved; the acceptance records only
                    # their irreversible binding and independently current guard.
                    owner = {"actor_id": authority.actor, "principal": asdict(binding.principal),
                        "session_binding_digest": canonical_digest(proof),
                        "request_digest": request_digest, "fence_token_digest": canonical_digest(permit.token),
                        "accepted_at_utc": now}
                    before = db.total_changes
                    result = commit(db, inputs, owner)
                    if db.total_changes != before:
                        store.cas_graph_recovery_metadata(metadata, target,
                            _capability=graph._GraphCoordinator__graph_capability)
                    db.execute(f"UPDATE {attempt_table} SET result_json=? WHERE bot=? AND persona=? AND operation_id=? AND attempt_id=?",
                        (canonical_serialize(result), *namespace.as_tuple, operation_id, attempt))
                    if db.execute("SELECT changes()").fetchone() != (1,):
                        raise StaleRead("D04 Owner original attempt changed before result retention")
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
        return result
    finally:
        port.finish_fence(scope, request_id="finish:" + attempt,
            request_digest="sha256:" + canonical_digest((attempt, permit.token, request_digest)))
        with store._lock:
            store._db.execute(f"UPDATE {attempt_table} SET finished=1 WHERE bot=? AND persona=? AND operation_id=? AND attempt_id=?",
                (*namespace.as_tuple, operation_id, attempt))


def adopt_current_d04_semantic_mapping_v3(reader, authority, lease, *,
        operation_id, profile_digest, expected_revision=0):
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("D04 semantic acceptance expected_revision must be nonnegative")
    request = {"action": "adopt_semantic_profile", "profile_digest": profile_digest,
               "expected_revision": expected_revision}
    def commit(db, inputs, owner):
        profile, namespace, issuer = inputs["profile"], authority.namespace, reader.graph._GraphCoordinator__d11_issuer
        if profile.profile_digest != profile_digest:
            raise ValueError("Owner selected semantic profile differs from exact installed profile")
        prior = _read_signed(db, issuer, TABLE, SIGN_KIND, namespace, operation_id=operation_id)
        if prior is not None:
            if prior[0]["owner"]["request_digest"] != owner["request_digest"]:
                raise ValueError("D04 semantic Owner operation ID reused with different input")
            return _receipt(prior)
        current = _read_signed(db, issuer, TABLE, SIGN_KIND, namespace)
        if (0 if current is None else current[0]["revision"]) != expected_revision:
            raise StaleRead("D04 semantic acceptance revision changed")
        asset = profile.bind(role_ref=inputs["role_ref"], persona_version=inputs["persona_version"])
        body = {"schema": "d04.owner-semantic-installation-original.v3", "namespace": asdict(namespace),
            "operation_id": operation_id, "revision": expected_revision + 1, "state": "active",
            "installation_ref": _installation_ref(reader, namespace), "manifest_sha256": reader.manifest_sha256,
            "profile_json": profile.profile_json, "profile_digest": profile.profile_digest,
            "owner": owner, "owner_guard": asdict(inputs["guard"]), "role_rows": inputs["role_rows"],
            "member_bindings": inputs["member_bindings"], "bound_asset": asdict(asset),
            "block_shares": inputs["block_shares"], "graph_revision": inputs["scope"].graph_revision,
            "graph_epoch": inputs["scope"].graph_epoch.revision}
        saved = _insert_signed(db, issuer, TABLE, SIGN_KIND, namespace, body)
        # Replay the production consumer before transaction commit.
        read_current_semantic_mapping_v3(reader, db, namespace)
        return _receipt(saved)
    return _owner_write(reader, authority, lease, operation_id=operation_id, request=request, commit=commit)


def _receipt(saved):
    body, digest = saved
    return {"status": "owner_semantic_profile_adopted", "operation_id": body["operation_id"],
        "acceptance_ref": "d04-semantic-acceptance:" + body["operation_id"],
        "acceptance_revision": body["revision"], "acceptance_digest": digest,
        "profile_digest": body["profile_digest"],
        "calibration_status": "engineering_unvalidated_owner_selection_required"}
