"""Closed foreground attempt inventory joined to the selected, real Core fence.

The Graph receipt is an occurrence record. Only the installed Core row proves
that its original write fence finished; neither a DTO nor its hash does so.
"""
from contextlib import closing
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sqlite3

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import FencePermitV2, canonical_bytes, from_wire
from ..authority_service.v2_fence_store import AuthorityV2FenceStore
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_originals_v1 import read_adopted_domain_operation_v1, _receipt_wire
from .restore_anchor import RestoreAnchor

TABLE = "graph_owner_domain_attempts_v3"
COLUMNS = ("bot", "persona", "operation_id", "request_digest", "attempt_id", "anchor_json",
    "graph_revision", "graph_epoch", "permit_json", "receipt_json")
PREFIX = "foreground-domain-"
_RECEIPT_FIELDS = frozenset({"schema", "domain", "operation_kind", "operation_id", "activity_id",
    "original_ref", "original_digest", "receipt", "receipt_digest", "job_states", "coverage",
    "missing_inputs", "continuation_ref", "outbox", "produced_originals"})


@dataclass(frozen=True, slots=True)
class ForegroundAttemptOriginalV1:
    namespace: NamespaceId
    operation_id: str
    attempt_id: str
    request_digest: str
    permit: FencePermitV2
    finish_digest: str
    row: tuple


def read_foreground_attempts_v1(db):
    """Decode exact Graph originals; this function grants no completion proof."""
    if not db.in_transaction:
        raise AuthorityUnavailable("C09 foreground inventory requires an actual SQL snapshot")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() is None:
        return {}
    columns = tuple(row[1] for row in db.execute(f"PRAGMA table_info({TABLE})"))
    if columns != COLUMNS:
        raise AuthorityUnavailable("C09 foreground mechanical attempt columns differ")
    originals = {}
    for row in db.execute(f"SELECT * FROM {TABLE} WHERE attempt_id LIKE 'foreground-domain-%'"):
        namespace = NamespaceId(row[0], row[1])
        operation, request_digest, attempt = row[2:5]
        if (type(request_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", request_digest) is None
                or attempt != PREFIX + request_digest[:48]
                or any(type(value) is not int or value < 0 for value in row[6:8])
                or row[8] is None or row[9] is None):
            raise AuthorityUnavailable("C09 foreground original is pending or has an invalid fixed identity; HOLD")
        permit = from_wire(json.loads(row[8]))
        anchor = RestoreAnchor(**json.loads(row[5]))
        recovery = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone()
        if recovery is None:
            raise AuthorityUnavailable("C09 foreground namespace has no real recovery identity")
        requirements = json.loads(recovery[0])
        if (type(permit) is not FencePermitV2 or permit.operation != "write" or permit.operation_id != attempt
                or permit.pinned_anchor != anchor or permit.generation != anchor.activation_generation
                or (permit.authority_id, permit.namespace) != (requirements["authority_id"], requirements["authority_namespace"])
                or canonical_serialize(asdict(anchor)) != row[5]
                or canonical_serialize(json.loads(row[8])) != row[8]):
            raise AuthorityUnavailable("C09 foreground original permit/anchor/namespace differs")
        original = read_adopted_domain_operation_v1(db, namespace, operation)
        saved = json.loads(row[9])
        if original is None or type(saved) is not dict or set(saved) != _RECEIPT_FIELDS:
            raise AuthorityUnavailable("C09 foreground saved receipt or actual adopted original is absent")
        from ..authority_service.current_foreground_activity_v1 import _DOMAINS
        receipt, payload = original["receipt"], original["payload"]
        if (_DOMAINS.get(original["operation_kind"]) != original["domain"]
                or saved["schema"] != "sylanne.domain-production-receipt.v1"
                or (saved["domain"], saved["operation_kind"], saved["operation_id"], saved["activity_id"])
                    != (original["domain"], original["operation_kind"], operation, receipt.activity_id)
                or saved["original_ref"] != original["domain"] + "-current:" + original["original_digest"][:48]
                or saved["original_digest"] != original["original_digest"]
                or saved["receipt"] != _receipt_wire(receipt) or saved["receipt_digest"] != canonical_digest(receipt)
                or payload["authority"]["activation_generation"] != permit.generation
                or receipt.status != "committed" or canonical_serialize(saved) != row[9]):
            raise AuthorityUnavailable("C09 foreground receipt differs from its actual W01 adoption")
        finish = "sha256:" + canonical_digest({"schema": "w01.foreground-domain-write.v1",
            "operation_id": operation, "request_digest": request_digest, "permit_token": permit.token})
        fence = db.execute("SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,"
            "post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation)).fetchone()
        if fence != (receipt.operation_digest, row[8], row[6], row[7], row[6] + 1, row[7] + 1,
                "finish:" + attempt, finish):
            raise AuthorityUnavailable("C09 foreground real bundle fence or foreground finish schema differs")
        if attempt in originals:
            raise AuthorityUnavailable("C09 foreground fixed attempt belongs to multiple Graph operations")
        originals[attempt] = ForegroundAttemptOriginalV1(namespace, operation, attempt, request_digest, permit, finish, tuple(row))
    return originals


def require_foreground_core_finished_v1(core_db, original):
    """The caller supplies the actual selected Core connection, never a row DTO."""
    if not core_db.in_transaction:
        raise AuthorityUnavailable("C09 foreground completion needs the actual Core snapshot")
    from ..authority_service.v2_fence_store import _TABLES
    if tuple(row[1] for row in core_db.execute("PRAGMA table_info(authority_v2_fences)")) != _TABLES["authority_v2_fences"]:
        raise AuthorityUnavailable("C09 foreground actual Core fence columns differ")
    row = AuthorityV2FenceStore._row(core_db, original.attempt_id)
    if (row is None or AuthorityV2FenceStore._permit(row) != original.permit
            or row[7] != canonical_bytes(original.permit) or row[6] != "finished"
            or row[8:11] != ("finish:" + original.attempt_id, original.finish_digest, None)):
        raise AuthorityUnavailable("C09 foreground true finished Core fence is absent or different; HOLD")
    return tuple(row)


def _selected_context_v1(control, operation_id):
    from ..authority_service.c09_storage_control_v1 import C09StorageControlV1
    if type(control) is not C09StorageControlV1:
        raise AuthorityUnavailable("C09 foreground requires installed storage control, not a supplied completion DTO")
    control.lease.require_held()
    context = control.read_verified_current_storage_v1()
    intent = control.read_operation_event_v1(operation_id, "INTENT")
    if (context.stage != "INTENT" or intent is None
            or intent["details"]["old_manifest_digest"] != context.manifest_digest):
        raise AuthorityUnavailable("C09 foreground source is not the current frozen INTENT")
    members = {item["role"]: item for item in context.manifest["members"]}
    return context, intent, members


def verify_foreground_attempts_from_selected_core_v1(db, *, control, operation_id):
    originals = read_foreground_attempts_v1(db)
    if not originals:
        return originals
    context, intent, members = _selected_context_v1(control, operation_id)
    graph_path = Path(db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True)
    if graph_path not in {Path(members["graph"]["resolved_path"]), Path(intent["details"]["targets"]["graph"])}:
        raise AuthorityUnavailable("C09 foreground Graph is neither the selected source nor its fixed candidate")
    core_path = Path(members["core"]["resolved_path"])
    with closing(sqlite3.connect(core_path.as_uri() + "?mode=ro", uri=True)) as core_db:
        core_db.execute("PRAGMA query_only=ON")
        core_db.execute("BEGIN")
        for original in originals.values():
            if original.permit.authority_id != control.authority_id:
                raise AuthorityUnavailable("C09 foreground fence belongs to another installed Authority")
            require_foreground_core_finished_v1(core_db, original)
        control.verify_member_v1(members["core"], prepared=False)
    context.require_current("maintenance")
    return originals


def foreground_core_dispositions_v1(core_db, *, control, operation_id, issue, mirror):
    """Join actual frozen Core rows to the signed mirror's exact Graph dispositions."""
    from ..authority_service.c09_graph_rebase_issue_v1 import verify_graph_rebase_issue_signature_v1
    from .c09_graph_rebase_candidate_v1 import graph_source_files_fingerprint_v1, _row_digest
    if not core_db.in_transaction:
        raise AuthorityUnavailable("C09 foreground retirement requires the actual frozen Core transaction")
    foreground_core = tuple(core_db.execute("SELECT operation_id FROM authority_v2_fences "
        "WHERE operation_id LIKE 'foreground-domain-%' AND namespace=?", (issue.namespace,)))
    context, intent, members = _selected_context_v1(control, operation_id)
    if Path(core_db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True) != Path(members["core"]["resolved_path"]):
        raise AuthorityUnavailable("C09 foreground retirement was not given the actual selected Core")
    verify_graph_rebase_issue_signature_v1(issue, control._key)
    source = Path(members["graph"]["resolved_path"])
    if (issue.source_path != str(source) or issue.target_path != intent["details"]["targets"]["graph"]
            or issue.certificate_digest != mirror.certificate.certificate_digest
            or issue.operation_id != operation_id or issue.authority_id != control.authority_id
            or issue.source_files_fingerprint != graph_source_files_fingerprint_v1(source)):
        raise AuthorityUnavailable("C09 foreground retirement signed Graph source/mirror differs")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("BEGIN")
        originals = read_foreground_attempts_v1(db)
        selected = {key: value for key, value in originals.items() if value.permit.namespace == issue.namespace}
        if {row[0] for row in foreground_core} != set(selected):
            raise AuthorityUnavailable("C09 foreground Core/Graph complete attempt inventory differs; HOLD")
        tables = tuple(item for item in mirror.certificate.table_manifests if item.table_name == TABLE)
        if selected and len(tables) != 1:
            raise AuthorityUnavailable("C09 foreground mirror has no exact attempt disposition inventory")
        dispositions = {} if not tables else {item.row_key_digest: item for item in tables[0].rows}
        result = {}
        for attempt, original in selected.items():
            core_row = require_foreground_core_finished_v1(core_db, original)
            key = canonical_digest((TABLE, original.row[:3]))
            disposition = dispositions.get(key)
            if (disposition is None or disposition.old_commitment != _row_digest(original.row)
                    or disposition.disposition not in {"preserved_exact", "derived_removed"}):
                raise AuthorityUnavailable("C09 foreground mirror attempt disposition differs from actual source")
            result[attempt] = (core_row, disposition.disposition)
    control.verify_member_v1(members["graph"], prepared=False)
    context.require_current("maintenance")
    return result
