"""Private, complete completed-Life inventory witness; never deletion rights.

The signed opaque payload is a precursor. No Graph disposition or V2 history
consumer accepts it yet, and populated carriers consequently remain HOLD.
"""
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from weakref import WeakValueDictionary

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize

SCHEMA = 'sylanne3.c09.completed-life-inventory.v2'
TABLES = ('graph_internal_life_content_originals_v1',
          'graph_internal_life_worker_originals_v2',
          'graph_internal_life_paid_originals_v2')
_ISSUED = WeakValueDictionary()


@dataclass(frozen=True)
class _LifeCompletedScopeV1:
    port: object
    snapshot: object
    signed_payload_json: str
    pointer_version: int
    manifest_digest: str


def _active(port, namespace, operation_id):
    from .c09_contact_finish_original_v1 import _PORTS
    from .c09_current_recovery_originals_v4 import (
        InstalledC09RecoveryOriginalsV4, ConnectionC09RecoveryOriginalsV4)
    from ..runtime.issuers import D11BudgetJobIssuer
    if (type(port) not in (InstalledC09RecoveryOriginalsV4, ConnectionC09RecoveryOriginalsV4)
            or _PORTS.get(id(port)) is not port):
        raise AuthorityUnavailable('C09 Life inventory requires actual registered port; HOLD')
    snapshot = port._current(namespace, operation_id)
    seal, _, _, _, business, core = snapshot
    issuer = getattr(port, 'budget_job_issuer', None)
    if (not business.in_transaction or not core.in_transaction
            or issuer is not None and (type(issuer) is not D11BudgetJobIssuer
            or issuer.resource_issuer is not port.resource_issuer)):
        raise AuthorityUnavailable('C09 Life inventory lacks frozen stores/installed issuer; HOLD')
    control = port._contact_control
    control.lease.require_held()
    current = control.read_verified_current_storage_v1(verify_files=False)
    intent = control.read_operation_event_v1(operation_id, 'INTENT')
    if current.stage != 'INTENT' or current.pointer_version != intent['pointer_version']:
        raise AuthorityUnavailable('C09 Life inventory is outside actual INTENT; HOLD')
    selected = {m['role']: Path(m['resolved_path']).resolve(strict=True) for m in current.manifest['members']}
    actual = tuple(Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True) for db in (business, core))
    if actual != (selected['graph'], selected['core']):
        raise AuthorityUnavailable('C09 Life inventory is not the selected actual stores; HOLD')
    return snapshot, issuer, control, current, intent


def capture_completed_life_inventory_v1(port, *, namespace, operation_id):
    """Authenticate every row, every job and actual Core obligations together."""
    from ..runtime.internal_life_completed_original_v1 import read_completed_internal_life_original_v1
    from ..runtime.internal_life_content_preparation_v1 import require_internal_life_content_schema_v1
    from ..runtime.c09_internal_life_content_v1 import validate_internal_life_content_inventory_row_v1
    from ..runtime.internal_life_content_worker_v2 import require_life_worker_schema_v2, validate_life_worker_inventory_row_v2
    from ..runtime.internal_life_paid_result_v2 import require_life_paid_schema_v2, validate_life_paid_inventory_v2, read_life_paid_original_v2
    from .internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2, internal_life_result_from_wire_v2
    snapshot, issuer, control, current, intent = _active(port, namespace, operation_id)
    seal, _, _, _, business, _ = snapshot
    checks = ((require_internal_life_content_schema_v1, validate_internal_life_content_inventory_row_v1),
              (require_life_worker_schema_v2, validate_life_worker_inventory_row_v2),
              (require_life_paid_schema_v2, validate_life_paid_inventory_v2))
    rows_by_table = {}; inventories = []; total_bytes = 0; count = 0
    for table, (schema, validate) in zip(TABLES, checks):
        present = business.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None
        if not present:
            rows_by_table[table] = ()
            inventories.append({'table': table, 'present': False, 'columns': [], 'schema_commitment': canonical_digest(()), 'rows': []})
            continue
        schema(business)
        columns = tuple(r[1] for r in business.execute(f'PRAGMA table_info({table})'))
        # Preflight bounded complete fetch, before decoding any content.
        size, length = business.execute(f'SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)),0) FROM {table}').fetchone()
        count += size; total_bytes += length
        if count > 100000 or total_bytes > 32*1024*1024:
            raise AuthorityUnavailable('C09 Life complete inventory exceeds finite bound; HOLD')
        rows = tuple(business.execute(f'SELECT * FROM {table} ORDER BY bot,persona,kind,4'))
        for row in rows:
            validate(columns, row)
            if row[:2] != port.namespace_id.as_tuple:
                raise AuthorityUnavailable('C09 Life inventory includes another namespace; HOLD')
        rows_by_table[table] = rows
        inventories.append({'table': table, 'present': True, 'columns': list(columns),
            'schema_commitment': canonical_digest(tuple(business.execute(
                'SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name', (table,)))),
            'rows': [{'kind': r[2], 'locator_commitment': canonical_digest(r[:4]),
                      'row_commitment': canonical_digest((table, columns, r))} for r in rows]})
    if count and issuer is None:
        raise AuthorityUnavailable('C09 populated Life inventory lacks installed D11 issuer; HOLD')
    prepared_rows = rows_by_table[TABLES[0]]
    jobs = tuple(sorted(r[3] for r in prepared_rows if r[2] == 'prepared'))
    if set((r[2], r[3]) for r in prepared_rows) != {(kind, job) for job in jobs for kind in ('prepared','prepare_commit')}:
        raise AuthorityUnavailable('C09 Life preparation inventory is not completed-only and exhaustive; HOLD')
    if set((r[2], r[3]) for r in rows_by_table[TABLES[1]]) != {(kind, job) for job in jobs for kind in ('binding','request','acquire_commit','call')}:
        raise AuthorityUnavailable('C09 Life complete worker inventory differs; HOLD')
    models = {} if not jobs else {v.call_id: v for v in port._model_originals(namespace, operation_id)}
    from ..runtime.c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v1, verify_c09_graph_barrier_v1
    from ..runtime.c09_graph_rebase_candidate_v1 import _dependency_closure, _affected_operations
    barrier = read_c09_erasure_barrier_v1(business, port.namespace_id, operation_id)
    if barrier is None:
        raise AuthorityUnavailable('C09 Life inventory lacks actual Graph barrier; HOLD')
    if verify_c09_graph_barrier_v1(business, port.namespace_id, operation_id,
            request_digest=barrier.request_digest, pending_receipt_digest=barrier.pending_receipt_digest) is None:
        raise AuthorityUnavailable('C09 Life actual Graph barrier is unauthenticated; HOLD')
    affected = _dependency_closure(business, set(barrier.affected_source_refs))
    affected_operations = _affected_operations(business, affected)
    expected_paid = set(); retained = []; job_dispositions = {}; paid_jobs = {}
    attempts_by_job = {}
    for row in rows_by_table[TABLES[2]]:
        if row[2] == 'read_attempt':
            raw = read_life_paid_original_v2(business, port.namespace_id, issuer, 'read_attempt', row[3])
            request = internal_life_result_from_wire_v2(raw, InternalLifeModelResultReadRequestV2)
            attempts_by_job.setdefault(request.job_id, []).append((row, request))
    for job_id in jobs:
        original = read_completed_internal_life_original_v1(business,
            namespace=port.namespace_id, issuer=issuer, job_id=job_id)
        model = models.get(original.intent.call_id)
        if (model is None or model.job_id != job_id or model.request_digest != original.intent.request_digest
                or model.provider_state != 'observed' or model.reservation_state != 'settled'
                or model.terminal_digest_or_none != canonical_digest(original.delivered.terminal_receipt)
                or model.observation_digest_or_none != original.delivered.observation.digest
                or any(u.actual_or_none is None or u.pending_known or u.debt or u.unknown_upper_bound
                       or u.settled != u.actual_or_none or u.settlement_id_or_none is None for u in model.units)):
            raise AuthorityUnavailable('C09 Life actual Core obligations are not fully closed; HOLD')
        expected_paid.update((kind, job_id) for kind in ('result','adoption_commit'))
        # All authentic attempts remain in inventory, including unselected retries.
        for row,request in attempts_by_job.get(job_id, ()):
            if replace(request, read_attempt_id=original.delivered.request.read_attempt_id) != original.delivered.request:
                raise AuthorityUnavailable('C09 Life signed retry changes its completed operation; HOLD')
            expected_paid.add(('read_attempt', row[3])); paid_jobs[row[3]] = job_id
        if ('read_attempt', original.delivered.request.read_attempt_id) not in expected_paid:
            raise AuthorityUnavailable('C09 Life delivered request absent from complete inventory; HOLD')
        members = {v.key.token for v in original.receipt.write_versions}
        references = {original.prepared.episode_ref, *(v.ref for v in original.validated_proof.historical_reads),
                      *(v.ref for v in original.validated_proof.current_reads), *members}
        operations = {original.prepared.prepare_operation_id, original.prepared.acquire_operation_id,
                      original.receipt.operation_id}
        touched = bool(references & affected or operations & affected_operations)
        if touched and (len(members)!=4 or not members <= affected):
            raise AuthorityUnavailable('C09 Life affected adoption lacks its complete four-member closure; HOLD')
        disposition = 'derived_removed' if touched else 'preserved_exact'
        job_dispositions[job_id] = disposition
        retained.append({'job_commitment': canonical_digest(job_id),
            'source_association_commitment': canonical_digest((tuple(sorted(references)), tuple(sorted(operations)), tuple(sorted(members)))),
            'disposition': disposition,
            'model_original_digest': model.original_digest,
            'adoption_commitment': canonical_digest(asdict(original.validated_proof)),
            'receipt_commitment': canonical_digest(original.receipt)})
    if {(r[2], r[3]) for r in rows_by_table[TABLES[2]]} != expected_paid:
        raise AuthorityUnavailable('C09 Life paid inventory contains unresolved/orphan carriers; HOLD')
    for family in inventories:
        for source, retained_row in zip(rows_by_table[family['table']], family['rows']):
            job_id = paid_jobs[source[3]] if family['table']==TABLES[2] and source[2]=='read_attempt' else source[3]
            retained_row['disposition'] = job_dispositions[job_id]
            retained_row['job_commitment'] = canonical_digest(job_id)
    body = {'schema': SCHEMA, 'authority_id': seal.authority_id,
        'installation_id': seal.installation_id, 'namespace': namespace,
        'operation_id': operation_id, 'pointer_version': current.pointer_version,
        'manifest_digest': current.manifest_digest,
        'quiescence_digest': intent['details']['quiescence_original']['quiescence_digest'],
        'graph_barrier_commitment': canonical_digest(barrier),
        'affected_atom_commitments': sorted(canonical_digest(v) for v in affected),
        'tables': inventories, 'completed_jobs': retained, 'status': 'authenticated_inventory_only_hold'}
    signed = control.sign_original_v1(SCHEMA, body, 'inventory_digest')
    scope = _LifeCompletedScopeV1(port, snapshot, canonical_serialize(signed), current.pointer_version, current.manifest_digest)
    _ISSUED[id(scope)] = scope
    require_completed_life_inventory_v1(scope)
    return scope


def require_completed_life_inventory_v1(scope):
    if type(scope) is not _LifeCompletedScopeV1 or _ISSUED.get(id(scope)) is not scope:
        raise AuthorityUnavailable('C09 Life caller DTO does not issue inventory authority; HOLD')
    raw = json.loads(scope.signed_payload_json)
    snapshot, _, control, current, _ = _active(scope.port, raw['namespace'], raw['operation_id'])
    if (snapshot is not scope.snapshot or current.pointer_version != scope.pointer_version
            or current.manifest_digest != scope.manifest_digest):
        raise AuthorityUnavailable('C09 Life inventory frozen source changed; HOLD')
    if (set(raw) != {'schema','authority_id','installation_id','namespace','operation_id',
            'pointer_version','manifest_digest','quiescence_digest','tables','completed_jobs',
            'status','key_id','inventory_digest','signature','graph_barrier_commitment','affected_atom_commitments'}
            or raw['schema'] != SCHEMA or raw['status'] != 'authenticated_inventory_only_hold'
            or tuple(v['table'] for v in raw['tables']) != TABLES):
        raise AuthorityUnavailable('C09 Life closed inventory schema differs; HOLD')
    control.verify_original_v1(raw, 'inventory_digest')
    business = snapshot[4]
    for table in raw['tables']:
        name = table['table']
        present = business.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None
        if not present:
            if table != {'table': name, 'present': False, 'columns': [], 'schema_commitment': canonical_digest(()), 'rows': []}:
                raise AuthorityUnavailable('C09 Life carrier vanished from frozen inventory; HOLD')
            continue
        columns = tuple(r[1] for r in business.execute(f'PRAGMA table_info({name})'))
        size, length = business.execute(f'SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)),0) FROM {name}').fetchone()
        if size > 100000 or length > 32*1024*1024:
            raise AuthorityUnavailable('C09 Life frozen inventory exceeds bound; HOLD')
        rows = business.execute(f'SELECT * FROM {name} ORDER BY bot,persona,kind,4').fetchall()
        metadata={v['locator_commitment']:{k:v[k] for k in ('disposition','job_commitment')} for v in table['rows']}
        actual = {'table': name, 'present': True, 'columns': list(columns),
            'schema_commitment': canonical_digest(tuple(business.execute(
                'SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name', (name,)))),
            'rows': [{'kind': r[2], 'locator_commitment': canonical_digest(r[:4]),
                      'row_commitment': canonical_digest((name, columns, r)),
                      **metadata.get(canonical_digest(r[:4]), {})} for r in rows]}
        if actual != table:
            raise AuthorityUnavailable('C09 Life complete frozen inventory changed; HOLD')
    return raw
