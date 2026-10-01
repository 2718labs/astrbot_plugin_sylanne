"""Map one actual paid/adopted appraisal under the installed Owner selection."""
from __future__ import annotations
from datetime import datetime, timezone
import json

from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, Owner
from ..runtime_contracts import canonical_digest
from ..model_broker.d04_appraisal import thaw_appraisal_request_v1
from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2
from ..domains.d04.root import decode_numeric_checkpoint
from ..domains.d04.numeric_drive import numeric_drive_id, TYPE_NAME as DRIVE_TYPE
from .d04_product_pipeline_v3 import ids, _freeze, _commit
from .d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3, read_d04_original_v3
from .d04_installed_stage_fence_v3 import run_installed_d04_stage_v3
from .d04_semantic_mapping_v3 import (read_current_d04_role_clock_v3,
    stage_current_d04_drive_in_transaction_v3, record_d04_mapping_acceptance_after_cas_v3)


def commit_post_c02_semantic_drive_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    namespace, identity = bundle.installation_policy.namespace, ids(bundle.installation_policy.namespace, c02_operation_id)
    policy = bundle.d04_semantic_drive
    if policy is None:
        return {"status": "semantic_policy_not_configured", "job_id": identity["job"]}
    reader = getattr(graph, "_GraphCoordinator__d04_semantic_mapping_reader", None)
    if reader is None:
        raise ValueError("D04 installed semantic reader absent")
    op = "d04-drive:" + identity["operation"]
    def commit(db, metadata, epoch, now, guard, role, current):
        original = read_current_d04_appraisal_original_v3(db, namespace, identity["job"])
        adopted = db.execute("SELECT receipt_json FROM graph_d04_installed_stage_attempts_v3 WHERE bot=? AND persona=? AND operation_id=? AND stage='adopt'",
            (*namespace.as_tuple, "d04-adopt:" + identity["operation"])).fetchone()
        receipt = None if adopted is None or adopted[0] is None else json.loads(adopted[0])
        if receipt is None or receipt.get("status") != "adopted" or original is None:
            raise ValueError("D04 semantic drive needs its actual adopted paid appraisal")
        frozen, snapshot, _, conversation = _freeze(graph, db, bundle, c02_operation_id, source_ref, role, current)
        if frozen != thaw_appraisal_request_v1(json.loads(original.frozen_json)):
            raise ValueError("D04 semantic appraisal source/role changed")
        from .budget import get_budget_lease, require_budget_family_admissible
        grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, policy.lease_id)
        budget = get_budget_lease(db, policy.lease_id)
        if ((policy.namespace, policy.installation_id, policy.grant_id, policy.grant_version) !=
                (namespace, bundle.installation_policy.installation_id, grant.grant_id, grant.version)
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                or (budget.bot_id, budget.persona_id) != namespace.as_tuple
                or grant.lease_id != budget.lease_id or grant.currency != budget.currency
                or policy.work_kind not in grant.allowed_work_kinds or grant.valid_until_utc <= now
                or budget.state != "active"):
            raise ValueError("D04 semantic drive current signed grant differs")
        require_budget_family_admissible(db, policy.lease_id)
        installed = reader(db, namespace)
        condition = reader.current_role_condition(db, namespace)
        mapping_id, mapping_version = reader.current_role_clock_identity(db, namespace)
        refs = tuple(sorted(ref for ref, _ in installed.block_shares))
        checkpoints = []
        for ref in refs:
            atom = snapshot.get(AtomKey.from_token(ref))
            if atom is None or not atom.valid:
                raise ValueError("D04 selected current numeric member missing")
            checkpoints.append(decode_authored_numeric_checkpoint_v2(atom.value)
                if atom.key.type_name == "d04.numeric_checkpoint.v2" else decode_numeric_checkpoint(atom.value))
        clock = read_current_d04_role_clock_v3(db, mapping_id=mapping_id,
            expected_mapping_version=mapping_version, checkpoints=tuple(checkpoints), checkpoint_refs=refs,
            wall_end_utc=datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"))
        atoms = {atom.key: atom for atom in snapshot.atoms}
        for ref in refs:
            for source in frozen.input.sources:
                key = AtomKey(Owner("persona", *namespace.as_tuple), DRIVE_TYPE,
                    numeric_drive_id(ref, source.source_ref.ref, clock.role_start, clock.role_end))
                if key not in atoms:
                    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
                    atoms[key] = GraphAtom(key, 0, {}, False) if row is None else GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
        snapshot = GraphSnapshot(tuple(atoms.values()), snapshot.epochs)
        suggestions = read_d04_original_v3(db, namespace, "appraisal_acceptance", receipt["appraisal_ref"])
        if suggestions is None:
            raise ValueError("D04 actual adopted appraisal original missing")
        suggestion = json.loads(suggestions[0]["suggestion_json"])
        cited = {row["interpretation_ref"] for row in suggestion["bundle"]["meaning_facets"]}
        levels = {item.candidate.evidence_status.value for item in frozen.input.interpretations if item.ref.ref in cited}
        if not levels or "refuted" in levels:
            raise ValueError("D04 cited competing interpretation is unavailable or refuted")
        interpretation_level = "contested" if "conflicted" in levels else "candidate"
        stage = stage_current_d04_drive_in_transaction_v3(db, namespace=namespace,
            appraisal_ref=receipt["appraisal_ref"], frozen=frozen, snapshot=snapshot, role=role,
            condition=condition, installed_mapping=installed, installed_mapping_reader=reader, dose_policy=policy,
            dose_grant_version=grant.version, clock=clock, audience=(conversation,), purpose="expression", interpretation_level=interpretation_level)
        if not stage.writes:
            raise ValueError("D04 mapping provides no qualified source drive")
        written = _commit(graph, db, metadata, epoch, op, identity["activity"], now,
            stage.writes, stage.read_versions, "d04.semantic_drive_adopted.v3")
        written_keys = {write.key for write in stage.writes}
        for write in stage.writes:
            for version in stage.read_versions:
                if version.revision > 0 and version.key not in written_keys:
                    db.execute("INSERT INTO graph_dependency_edges(dependent_token,dependency_token,"
                        "dependency_revision,edge_kind,operation_id) VALUES(?,?,?,?,?)",
                        (write.key.token, version.key.token, version.revision, "historical_provenance", op))
        record_d04_mapping_acceptance_after_cas_v3(db, stage)
        return {"status": "drive_adopted", "operation_id": op, "mapping_ref": stage.original_ref,
            "mapping_digest": stage.original_digest, "clock": json.loads(stage.original_payload_json)["clock"], "root_ref": refs[0],
            "appraisal_ref": receipt["appraisal_ref"], "graph_receipt_digest": canonical_digest(written)}
    return run_installed_d04_stage_v3(graph, bootstrap, bundle,
        c02_operation_id=c02_operation_id, source_ref=source_ref, operation_id=op, stage="drive",
        request_digest=canonical_digest(("d04.installed_drive.v3", namespace, c02_operation_id, source_ref,
            {name: dict(getattr(policy, name)) if name.startswith("mechanism_max_") else getattr(policy, name)
             for name in policy.__dataclass_fields__})),
        commit=commit, semantic=True)
