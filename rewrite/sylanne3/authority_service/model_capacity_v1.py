"""Bounded Core-wide model capacity from the existing authoritative rows."""

from __future__ import annotations

import json
import sqlite3

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest

GLOBAL_LIMIT_V1 = NAMESPACE_LIMIT_V1 = 1
BACKGROUND_GLOBAL_LIMIT_V1 = BACKGROUND_NAMESPACE_LIMIT_V1 = 1
CENSUS_ITEMS_V1 = 512
CENSUS_PAYLOAD_BYTES_V1 = 8_388_608
ORIGINAL_IDENTITY_BYTES_V1 = 64 * 1024


def _not_dispatched_digest(call_id, operation_id, token):
    # SQLite calls this only with scalar projections; no ledger body is loaded.
    if any(type(item) is not str or not item or len(item.encode("utf-8")) > 1024
           for item in (call_id, operation_id, token)):
        return None
    return "sha256:" + canonical_digest({"status": "not_dispatched",
        "call_id": call_id, "operation_id": operation_id, "token": token})


def _anchor_digest(raw):
    if type(raw) is not str or len(raw.encode("utf-8")) > 8192:
        return None
    try:
        value = json.loads(raw)
        return canonical_digest(value) if type(value) is dict else None
    except (ValueError, TypeError):
        return None


def _ledger_source_commitment(*row):
    """Match capture_frozen_model_budget_originals_v1's exact ledger commitment."""
    # SQL bounds each argument before it crosses into Python. This row has no
    # BLOB columns, so the capture producer's material tuple is the row itself.
    if any(type(value) is not str for value in row[:6]) or row[6] is not None and type(row[6]) is not str:
        return None
    columns = ("call_id", "operation_id", "namespace", "subject",
               "identity_json", "state", "observation_digest")
    return canonical_digest(("authority_model_egress_v1", columns, row))


def install_model_capacity_functions_v1(db):
    """Connection-local functions; no additional persistence or capacity cache."""
    db.create_function("model_capacity_not_dispatched_v1", 3,
        _not_dispatched_digest, deterministic=True)
    db.create_function("model_capacity_anchor_v1", 1, _anchor_digest, deterministic=True)
    db.create_function("model_capacity_ledger_source_v1", 7,
        _ledger_source_commitment, deterministic=True)


def _scalar(expression):
    # Oversized data stays inside SQLite; NULL keeps an invalid row charged.
    return (f"CASE WHEN length(CAST({expression} AS BLOB)) <= 1024 "
            f"THEN {expression} END")


def _retained_sql():
    return """SELECT r.namespace,r.call_id,
        json_extract(r.original_json,'$.model_operation_id') operation_id,
        json_extract(r.original_json,'$.request_digest') request_digest,
        json_extract(r.original_json,'$.provider_state') state,
        r.original_digest,
        json_extract(r.original_json,'$.source_row_commitments') source_row_commitments,
        CASE WHEN json_extract(r.original_json,'$.namespace')=r.namespace
          AND json_extract(r.original_json,'$.call_id')=r.call_id
          AND json_extract(r.original_json,'$.operation_id')=r.operation_id
          AND json_extract(r.original_json,'$.original_digest')=r.original_digest
          AND ((json_extract(r.original_json,'$.provider_state')='observed'
          AND length(json_extract(r.original_json,'$.observation_digest_or_none'))=64
          AND length(json_extract(r.original_json,'$.terminal_digest_or_none'))=64) OR
          (json_extract(r.original_json,'$.schema')='sylanne3.c09.model-no-dispatch-budget-original.v2'
          AND json_extract(r.original_json,'$.provider_state')='prepared'
          AND json_extract(r.original_json,'$.reservation_state')='settled'
          AND json_extract(r.original_json,'$.observation_digest_or_none') IS NULL
          AND json_extract(r.original_json,'$.terminal_digest_or_none') IS NULL
          AND length(json_extract(r.original_json,'$.no_dispatch_witness_digest'))=64
          AND NOT EXISTS (SELECT 1 FROM json_each(r.original_json,'$.units') u
              WHERE json_extract(u.value,'$.actual_or_none')<>0 OR json_extract(u.value,'$.actual_or_none') IS NULL
              OR json_extract(u.value,'$.unknown_upper_bound')<>0 OR json_extract(u.value,'$.pending_known')<>0)))
        THEN 1 ELSE 0 END released
        FROM authority_c09_model_budget_originals_v1 r"""


def _moved_terminal_ledger_sql():
    """A consumed ledger is passive only with its exact sealed C09 terminal."""
    row_digest = "model_capacity_ledger_source_v1(" + ",".join((
        _scalar("original.call_id"), _scalar("original.operation_id"),
        _scalar("original.namespace"), _scalar("original.subject"),
        f"CASE WHEN length(CAST(original.identity_json AS BLOB))<={ORIGINAL_IDENTITY_BYTES_V1} "
        "THEN original.identity_json END",
        _scalar("original.state"), _scalar("original.observation_digest"),
    )) + ")"
    return f"""EXISTS (
        SELECT 1 FROM retained r
        JOIN authority_model_egress_v1 original ON original.call_id=l.call_id
        JOIN authority_c09_consumed_execution_v1 consumed_call
          ON consumed_call.namespace=r.namespace AND consumed_call.kind='model_call'
         AND consumed_call.item_id=r.call_id
         AND consumed_call.operation_id=r.operation_id
         AND consumed_call.original_commitment=r.original_digest
        JOIN authority_c09_consumed_execution_v1 consumed_operation
          ON consumed_operation.namespace=r.namespace
         AND consumed_operation.kind='model_operation'
         AND consumed_operation.item_id=r.operation_id
         AND consumed_operation.operation_id=r.operation_id
         AND consumed_operation.original_commitment=r.original_digest
         AND consumed_operation.facts_pin_digest=consumed_call.facts_pin_digest
        JOIN authority_c09_consumed_execution_v1 consumed_fence
          ON consumed_fence.namespace=r.namespace AND consumed_fence.kind='fence'
         AND consumed_fence.item_id=r.operation_id
         AND consumed_fence.operation_id=r.operation_id
         AND consumed_fence.facts_pin_digest=consumed_call.facts_pin_digest
        WHERE r.released=1 AND r.state=l.state AND r.state IN ('observed','prepared')
          AND r.namespace=l.namespace AND r.call_id=l.call_id
          AND r.operation_id=l.operation_id AND r.request_digest=l.request_digest
          AND NOT EXISTS (SELECT 1 FROM authority_v2_fences f
              WHERE f.operation_id=l.operation_id)
          AND EXISTS (SELECT 1 FROM json_each(r.source_row_commitments) commitment
              WHERE commitment.type='text' AND commitment.value={row_digest})
    )"""


def _ledger_sql():
    identity = "l.identity_json"
    permit = "CAST(f.permit AS TEXT)"
    equalities = [
        "b.operation_id=l.operation_id", "b.token=f.token",
        "f.operation_id=l.operation_id", "f.namespace=l.namespace", "f.subject=l.subject",
        "f.pending IS NULL",
        f"json_extract({permit},'$.operation')='model_egress'",
    ]
    for field, expression in (
            ('authority_id', f"json_extract({identity},'$.authority_id')"),
            ('namespace', 'l.namespace'), ('subject', 'l.subject'),
            ('operation_id', 'l.operation_id'), ('token', 'b.token'),
            ('fence_epoch', f"json_extract({identity},'$.fence_epoch')"),
            ('revision', f"json_extract({identity},'$.fence_revision')"),
            ('generation', f"json_extract({identity},'$.authority_activation_generation')")):
        equalities.append(f"json_extract({permit},'$.{field}')={expression}")
    equalities.extend([
        f"json_extract({identity},'$.call_id')=l.call_id",
        f"json_extract({identity},'$.operation_id')=l.operation_id",
        f"json_extract({identity},'$.namespace')=l.namespace",
        f"json_extract({identity},'$.subject')=l.subject",
        f"json_extract({identity},'$.fence_token')=f.token",
        f"json_extract({identity},'$.fence_epoch')=f.fence_epoch",
        f"json_extract({identity},'$.fence_revision')=f.revision",
        f"json_extract({identity},'$.anchor_digest')="
            f"model_capacity_anchor_v1(CASE WHEN length(CAST(json_extract({permit},'$.pinned_anchor') "
            f"AS BLOB))<=8192 THEN json_extract({permit},'$.pinned_anchor') END)",
    ])
    binding = " AND ".join(equalities)
    terminal = ["s.status='completed'", "s.observation_digest=l.observation_digest",
        "a.report_digest IS NOT NULL", "a.receipt_json IS NOT NULL",
        "json_extract(a.admission_json,'$.admission_id')=a.admission_id",
        "json_extract(a.admission_json,'$.call_id')=l.call_id",
        "json_extract(a.admission_json,'$.operation_id')=l.operation_id",
        "json_extract(a.admission_json,'$.namespace')=l.namespace",
        "json_extract(a.admission_json,'$.subject')=l.subject",
        f"json_extract(a.admission_json,'$.authority_id')=json_extract({identity},'$.authority_id')",
        f"json_extract(a.admission_json,'$.request_digest')=json_extract({identity},'$.request_digest')",
        f"json_extract(a.admission_json,'$.provider_config_digest')=json_extract({identity},'$.provider_config_digest')",
        "json_extract(a.receipt_json,'$.report_digest')=a.report_digest",
        "json_extract(a.receipt_json,'$.observation_digest')=l.observation_digest",
        "json_extract(a.receipt_json,'$.finish_digest')=f.finish_request_digest",
        "f.finish_request_digest='sha256:' || l.observation_digest"]
    for field in ('admission_id','call_id','request_digest','installation_id','host_incarnation'):
        terminal.append(f"json_extract(a.receipt_json,'$.{field}')="
                        f"json_extract(a.admission_json,'$.{field}')")
    released = (f"{binding} AND f.state='finished' AND f.finish_request_id=l.call_id AND "
        "((l.state='prepared' AND a.call_id IS NULL AND l.observation_digest IS NULL "
        "AND s.call_id IS NULL AND f.finish_request_digest="
        f"model_capacity_not_dispatched_v1({_scalar('l.call_id')},{_scalar('l.operation_id')},{_scalar('f.token')})) OR "
        f"(l.state='observed' AND {' AND '.join(terminal)}))")
    return f"""SELECT l.namespace,l.call_id,l.operation_id,
        json_extract(l.identity_json,'$.request_digest') request_digest,l.state,
        CASE WHEN {released} THEN 1 ELSE 0 END released
        FROM authority_model_egress_v1 l
        LEFT JOIN authority_model_egress_bindings_v1 b ON b.call_id=l.call_id
        LEFT JOIN authority_v2_fences f ON f.operation_id=l.operation_id
        LEFT JOIN authority_model_egress_observation_status_v1 s ON s.call_id=l.call_id
        LEFT JOIN authority_model_admissions_v2 a ON a.call_id=l.call_id"""


def model_capacity_census_locked_v1(db, namespace, *, exclude=None, selected=None):
    """Count unresolved calls across this Core DB, with no owner/incarnation filter.

    Older ledger rows have no work kind. Every unresolved call conservatively
    consumes background capacity; the fixed global limit of one bounds admission.
    C09 money settlement never decides execution release.
    """
    if not db.in_transaction:
        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
    try:
        has_retained = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='authority_c09_model_budget_originals_v1'").fetchone() is not None
        retained = (_retained_sql() if has_retained else
            "SELECT NULL namespace,NULL call_id,NULL operation_id,NULL request_digest,"
            "NULL state,NULL original_digest,NULL source_row_commitments,1 released WHERE 0")
        has_consumed = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='authority_c09_consumed_execution_v1'").fetchone() is not None
        moved_terminal = _moved_terminal_ledger_sql() if has_retained and has_consumed else "0"
        sql = f"""WITH retained AS ({retained}), ledger AS ({_ledger_sql()}),
            candidates AS (
                SELECT l.namespace,l.call_id,l.operation_id,l.request_digest,l.state,0 retained
                FROM ledger l WHERE l.released=0 AND NOT ({moved_terminal})
                UNION ALL
                SELECT namespace,call_id,operation_id,request_digest,state,1 retained
                FROM retained WHERE released=0
                UNION ALL
                SELECT f.namespace,COALESCE(r.call_id,'fence:' || f.operation_id),
                    f.operation_id,r.request_digest,'unresolved',0
                FROM authority_v2_fences f
                LEFT JOIN retained r ON r.namespace=f.namespace AND r.operation_id=f.operation_id
                WHERE json_extract(CAST(f.permit AS TEXT),'$.operation')='model_egress'
                  AND NOT EXISTS (SELECT 1 FROM authority_model_egress_v1 l
                      WHERE l.operation_id=f.operation_id)
                  AND COALESCE(r.released,0)=0
                UNION ALL
                SELECT json_extract(a.admission_json,'$.namespace'),a.call_id,
                    json_extract(a.admission_json,'$.operation_id'),
                    json_extract(a.admission_json,'$.request_digest'),'unresolved',0
                FROM authority_model_admissions_v2 a
                WHERE NOT EXISTS (SELECT 1 FROM authority_model_egress_v1 l
                    WHERE l.call_id=a.call_id)
            ), projected AS (
                SELECT {','.join(_scalar(field) + ' AS ' + field for field in ('namespace','call_id','operation_id','request_digest','state'))},
                    retained FROM candidates
            ), eligible AS (
                SELECT * FROM projected WHERE NOT COALESCE(
                    retained=0 AND namespace=? AND call_id=? AND operation_id=? AND request_digest=?,0)
            ), identities AS (
                SELECT namespace,call_id FROM eligible GROUP BY namespace,call_id
            ) SELECT
                (SELECT count(*) FROM identities),
                (SELECT count(*) FROM identities WHERE namespace=?),
                (SELECT COALESCE(max(CASE WHEN
                    typeof(namespace)!='text' OR length(namespace)=0 OR
                    typeof(call_id)!='text' OR length(call_id)=0 OR
                    typeof(operation_id)!='text' OR length(operation_id)=0 OR
                    typeof(request_digest)!='text' OR length(request_digest)=0 OR
                    typeof(state)!='text' OR length(state)=0
                    THEN 1 ELSE 0 END),0) FROM eligible),
                (SELECT COALESCE(sum(length(CAST(json_array(namespace,call_id,
                    operation_id,request_digest,state,retained) AS BLOB))),0) FROM eligible)"""
        # Only four scalars cross into Python. De-duplicate before the 512-item
        # bound; duplicate retained/fence witnesses still consume the byte cap.
        aggregate = db.execute(sql,(*((None,)*4 if exclude is None else exclude),namespace)).fetchone()
        selected_released = False
        if selected is not None:
            selected_released = db.execute(f"SELECT 1 FROM ({_ledger_sql()}) "
                "WHERE namespace=? AND call_id=? AND operation_id=? AND request_digest=? "
                "AND released=1",selected).fetchone() is not None
    except sqlite3.Error as exc:
        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED") from exc
    global_count, namespace_count, invalid, encoded_bytes = aggregate
    if global_count > CENSUS_ITEMS_V1 or encoded_bytes > CENSUS_PAYLOAD_BYTES_V1:
        raise AuthorityUnavailable("MODEL_CAPACITY_CENSUS_OVERFLOW")
    if invalid:
        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
    fact = {"global_count": global_count,"namespace_count": namespace_count,
        "background_count": global_count,"namespace_background_count": namespace_count,
        "capacity_available": global_count < GLOBAL_LIMIT_V1
            and namespace_count < NAMESPACE_LIMIT_V1
            and global_count < BACKGROUND_GLOBAL_LIMIT_V1
            and namespace_count < BACKGROUND_NAMESPACE_LIMIT_V1}
    if selected is not None:
        fact["selected_released"] = selected_released
    return fact


def require_model_capacity_locked_v1(db, namespace, *, exclude=None):
    fact = model_capacity_census_locked_v1(db, namespace, exclude=exclude)
    if not fact["capacity_available"]:
        raise AuthorityUnavailable("MODEL_CAPACITY_GLOBAL_FULL")
    return fact


def retained_model_capacity_match_locked_v1(db, draft, installation_id):
    """Content-free retained identity lookup; no old permit is returned."""
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='authority_c09_model_budget_originals_v1'").fetchone()
    if exists is None:
        return False
    fields = ('authority_id','installation_id','model_operation_id','job_id',
        'acquire_operation_id','request_digest','binding_digest')
    expected = (draft.authority_id,installation_id,draft.operation_id,draft.job_id,
        draft.acquire_operation_id,draft.request_digest,draft.binding_digest)
    comparisons = " AND ".join(_scalar("json_extract(original_json,'$."+field+"')")+"=?"
        for field in fields)
    count, invalid = db.execute("SELECT count(*),COALESCE(max(CASE WHEN COALESCE("+
        comparisons+",0) THEN 0 ELSE 1 END),0) FROM authority_c09_model_budget_originals_v1 "
        "WHERE namespace=? AND call_id=?",(*expected,draft.namespace,draft.call_id)).fetchone()
    if invalid:
        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
    return count != 0
