"""Installed Authority admission for the registered, paused Graph upgrade."""
from dataclasses import dataclass
from pathlib import Path
import json
import threading
import time
from uuid import UUID

from .contract import AuthorityUnavailable
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from ..contracts import canonical_json
from ..runtime_contracts import NamespaceId

TABLE = "authority_graph_catalogue_upgrades_v1"
DDL = f"CREATE TABLE IF NOT EXISTS {TABLE}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,pause_operation_id TEXT NOT NULL,target_cohort_ref TEXT NOT NULL,source_catalogue_hash TEXT NOT NULL,target_catalogue_hash TEXT NOT NULL,target_manifest_digest TEXT NOT NULL,storage_json TEXT NOT NULL,owner_head TEXT NOT NULL,started_at REAL NOT NULL,state TEXT NOT NULL,receipt_json TEXT,request_json TEXT NOT NULL,PRIMARY KEY(namespace,operation_id))"
COLUMNS = ('namespace','operation_id','request_digest','pause_operation_id','target_cohort_ref',
    'source_catalogue_hash','target_catalogue_hash','target_manifest_digest','storage_json','owner_head',
    'started_at','state','receipt_json','request_json')
_REQUEST_FIELDS = frozenset(('namespace','authority_namespace','installation_id','operation_id','pause_operation_id',
    'target_cohort_ref','target_cohort_digest','source_catalogue_hash','target_catalogue_hash',
    'target_manifest_digest','actor','storage','selected_pointer'))


def require_declared_catalogue_cohort_transition_v1(source, target, source_configuration, target_configuration,
        *, source_catalogue_hash, target_catalogue_hash):
    """Compare exact configurations with one explicitly named catalogue delta.

    Both cohort commitments retain both actual catalogue hashes. This comparison
    authorizes no new budget, actor, TLS, provider, process or filesystem scope.
    Package path/manifest substitutions are the already declared cohort fields.
    """
    old_hash = source_configuration['host_profile']['installation_policy']['catalogue_hash']
    if old_hash not in {source_catalogue_hash,target_catalogue_hash}:
        raise AuthorityUnavailable('selected source package is outside the registered catalogue transition')
    allowed = {
        ('deployment','package_root'): (source.package.package_root,target.package.package_root),
        ('deployment','trusted_manifest_sha256'): (source.package.manifest_sha256,target.package.manifest_sha256),
        ('deployment','assets_path'): (source_configuration['deployment']['assets_path'],target_configuration['deployment']['assets_path']),
        ('assets','installations_v2',0,'manifest_digest'): (source.package.manifest_sha256,target.package.manifest_sha256),
        ('assets','c04_installations_v3',0,'package_root'): (source.package.package_root,target.package.package_root),
        ('assets','c04_installations_v3',0,'formal_manifest_sha256'): (source.package.manifest_sha256,target.package.manifest_sha256),
        ('host_profile','installation_policy','manifest_digest'): (source.package.manifest_sha256,target.package.manifest_sha256),
        ('host_profile','installation_policy','catalogue_hash'): (old_hash,target_catalogue_hash),
    }
    if (source.installation_id != target.installation_id
            or source.credential_profile_directory != target.credential_profile_directory
            or source.supervisor_policy_digest != target.supervisor_policy_digest
            or source.compatibility_plan_ref != target.compatibility_plan_ref):
        raise AuthorityUnavailable('catalogue transition changes the installed cohort authority')
    def compare(left, right, path=()):
        if path in allowed:
            if (left,right) != allowed[path]:
                raise AuthorityUnavailable('declared catalogue/package delta differs')
        elif type(left) is dict and type(right) is dict and set(left) == set(right):
            for name in left: compare(left[name],right[name],(*path,name))
        elif type(left) is list and type(right) is list and len(left) == len(right):
            for index,(a,b) in enumerate(zip(left,right)): compare(a,b,(*path,index))
        elif type(left) is not type(right) or left != right:
            raise AuthorityUnavailable('catalogue transition changes configuration outside its exact declared fields')
    compare(source_configuration,target_configuration)


def require_no_pending_catalogue_upgrade_in_tx_v1(db, namespace):
    if not db.in_transaction:
        raise ValueError("catalogue upgrade exclusion requires the Core transaction")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone():
        if db.execute(f"SELECT 1 FROM {TABLE} WHERE namespace=? AND state!='completed' LIMIT 1", (namespace,)).fetchone():
            raise AuthorityUnavailable("registered catalogue conversion must finish before Host resume")


def require_catalogue_operation_unconsumed_in_tx_v1(db, namespace, operation_id):
    if not db.in_transaction:
        raise AuthorityUnavailable('catalogue replay check requires actual Core transaction')
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
        if db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? "
                "AND kind='catalogue_upgrade_operation' AND item_id=?", (namespace,operation_id)).fetchone():
            raise AuthorityUnavailable('catalogue operation was retired by C09 and cannot be replayed')


def validate_catalogue_upgrade_core_schema_v1(db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if row is not None and (row[0] != DDL.replace(' IF NOT EXISTS','')
            or tuple(item[1] for item in db.execute('PRAGMA table_info('+TABLE+')')) != COLUMNS):
        raise AuthorityUnavailable('catalogue Core schema differs')


def validate_catalogue_upgrade_core_row_v1(columns, row):
    """Decode the complete frozen request; C09 retires it into its consumed ledger."""
    from .d12_package_files_v2 import decode_package_selection_v2, _digest
    from ..runtime.graph_catalogue_upgrade_v1 import _json, _sha, _number, registered_source_v1, decode_catalogue_receipt_v1
    import math
    if columns != COLUMNS or len(row) != len(COLUMNS):
        raise AuthorityUnavailable('catalogue Core row columns differ')
    try:
        request = _json(row[13]); storage = _json(row[8])
        if type(request) is not dict or set(request) != _REQUEST_FIELDS or _digest(request) != row[2]:
            raise ValueError('catalogue Core frozen request differs')
        operation = UUID(row[1])
        namespace = NamespaceId(**request['namespace'])
        if operation.version != 4 or str(operation) != row[1]:
            raise ValueError('catalogue Core operation differs')
        if tuple(request[name] for name in ('authority_namespace','operation_id','pause_operation_id',
                'target_cohort_ref','source_catalogue_hash','target_catalogue_hash','target_manifest_digest')) != (
                    row[0],row[1],row[3],row[4],row[5],row[6],row[7]) or request['storage'] != storage:
            raise ValueError('catalogue Core request/row binding differs')
        for name in ('authority_namespace','installation_id','pause_operation_id','target_cohort_ref','actor'):
            if type(request[name]) is not str or not request[name]:
                raise ValueError('catalogue Core request identity absent')
        for value in (row[2],row[5],row[6],row[7],request['target_cohort_digest']): _sha(value)
        registered_source_v1(row[5]); _sha(row[9].removeprefix('sha256:'))
        if type(storage) is not dict or set(storage) != {'pointer_version','manifest_digest','storage_generation','members'}:
            raise ValueError('catalogue storage identity fields differ')
        _number(storage['pointer_version']); _number(storage['storage_generation']); _sha(storage['manifest_digest'])
        if type(storage['members']) is not list or len(storage['members']) != 4:
            raise ValueError('catalogue storage members differ')
        roles = set()
        for member in storage['members']:
            if type(member) is not dict or set(member) != {'role','resolved_path','device','file_id','incarnation_or_journal_id'}:
                raise ValueError('catalogue member identity fields differ')
            roles.add(member['role']); _number(member['device']); _number(member['file_id'])
            if not Path(member['resolved_path']).is_absolute() or type(member['incarnation_or_journal_id']) is not str or not member['incarnation_or_journal_id']:
                raise ValueError('catalogue member identity differs')
        if roles != {'core','deletion','execution','graph'}:
            raise ValueError('catalogue storage member roles differ')
        selected = decode_package_selection_v2(request['selected_pointer'])
        if selected.installation_id != request['installation_id']:
            raise ValueError('catalogue original selection installation differs')
        if (type(row[10]) not in (int,float) or not math.isfinite(row[10]) or row[10] < 0
                or row[11] not in {'pending','completed'} or row[11] == 'completed' and row[12] is None):
            raise ValueError('catalogue Core phase differs')
        receipt = None
        if row[12] is not None:
            raw = _json(row[12])
            receipt = decode_catalogue_receipt_v1(row[12], namespace=namespace.as_tuple, operation_id=row[1])
            if ((receipt['phase'] == 'completed') != (row[11] == 'completed')
                    or tuple(receipt[name] for name in ('source_catalogue_hash','target_catalogue_hash','target_manifest_digest')) != row[5:8]):
                raise ValueError('catalogue Core completion binding differs')
        return request, receipt
    except (ValueError,TypeError,KeyError,AttributeError) as exc:
        raise AuthorityUnavailable('catalogue Core original cannot be classified') from exc


def require_selected_catalogue_target_in_tx_v1(db, lifecycle):
    """A completed conversion does not permit restarting its old source package."""
    require_no_pending_catalogue_upgrade_in_tx_v1(db, lifecycle.namespace)
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone():
        return
    validate_catalogue_upgrade_core_schema_v1(db)
    row = db.execute(f'SELECT * FROM {TABLE} WHERE namespace=? ORDER BY started_at DESC,operation_id DESC LIMIT 1',
                     (lifecycle.namespace,)).fetchone()
    if row is None:
        return
    request, receipt = validate_catalogue_upgrade_core_row_v1(COLUMNS, row)
    service = getattr(lifecycle, '_catalogue_upgrade_service_v1', None)
    if type(service) is not InstalledGraphCatalogueUpgradeV1 or service.lifecycle is not lifecycle:
        raise AuthorityUnavailable('completed catalogue awaits its actual installed package qualifier')
    from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
    installation, target = service.files.read_registered_cohort_v2(row[4])
    read_verified_configuration_cohort_v2(target)
    selected, cohort, configuration = service.files.read_selected_configuration_cohort_v2()
    if (installation != lifecycle.installation_id or selected.installation_id != installation
            or target.cohort_digest != request['target_cohort_digest'] or target.package.manifest_sha256 != row[7]
            or cohort.identity_commitment != target.identity_commitment
            or selected.manifest_sha256 != lifecycle.expected_manifest_digest
            or configuration['host_profile']['installation_policy']['catalogue_hash'] != row[6]):
        raise AuthorityUnavailable('completed catalogue awaits qualified target package selection; source Host resume forbidden')
    import sqlite3
    from ..runtime.graph_catalogue_upgrade_v1 import current_catalogue_hash_v1
    context, storage = lifecycle._storage()
    graph_path = next(item['resolved_path'] for item in storage['members'] if item['role'] == 'graph')
    graph = sqlite3.connect(Path(graph_path).as_uri()+'?mode=ro', uri=True, isolation_level=None)
    try:
        graph.execute('BEGIN')
        if current_catalogue_hash_v1(graph) != row[6]:
            raise AuthorityUnavailable('selected package and completed Graph catalogue differ')
    finally:
        graph.close()
    context.require_current('business')


@dataclass(frozen=True, slots=True)
class _CatalogueBatchScopeV1:
    namespace: NamespaceId
    operation_id: str
    request_digest: str
    source_catalogue_hash: str
    target_catalogue_hash: str
    target_manifest_digest: str
    started_at: float
    graph_path: str
    issuer: object
    thread_id: int


def require_issued_catalogue_batch_v1(scope):
    if (type(scope) is not _CatalogueBatchScopeV1
            or type(scope.issuer) is not InstalledGraphCatalogueUpgradeV1
            or scope.issuer._issued is not scope
            or scope.thread_id != threading.get_ident()
            or not scope.issuer.lifecycle.core._db.in_transaction):
        raise AuthorityUnavailable("actual current Authority catalogue batch admission required")
    return scope


class InstalledGraphCatalogueUpgradeV1:
    """One call advances one durable batch; caller retries the same operation."""
    def __init__(self, *, lifecycle, package_files, target_registry):
        from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        from ..graph_types import TypeRegistry
        if (type(lifecycle) is not InstalledD12InstallationLifecycleV1
                or type(package_files) is not InstalledPackageSelectionFilesV2
                or type(target_registry) is not TypeRegistry):
            raise TypeError("actual installed lifecycle, package registry and type registry required")
        self.lifecycle, self.files = lifecycle, package_files
        self.registry = target_registry.freeze()
        self._issued = None
        lifecycle._catalogue_upgrade_service_v1 = self

    def install_schema(self, administrator_credential):
        self.lifecycle.core._require(administrator_credential, "d12_lifecycle_install", self.lifecycle.namespace)
        with self.lifecycle.core._tx() as db:
            db.execute(DDL)
            validate_catalogue_upgrade_core_schema_v1(db)

    def _reply(self, receipt, selected, target):
        # Selection readiness is an observation beside the immutable Graph
        # receipt. This service never claims to retire/restart its own process.
        state = 'catalogue_in_progress'
        if receipt['phase'] == 'completed':
            state = ('target_selected_resume_required' if selected.cohort_digest == target.cohort_digest
                and selected.manifest_sha256 == self.lifecycle.expected_manifest_digest
                else 'awaiting_qualified_package_switch')
        return {**receipt, 'package_switch_status': state}

    def advance_current_upgrade_v1(self, *, credential, actor, session_token, session_request,
            operation_id, pause_operation_id, target_cohort_ref, source_catalogue_hash):
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        from .d12_package_files_v2 import _digest
        from ..graph_store import GraphStore
        from ..runtime.graph_catalogue_upgrade_v1 import registered_source_registry_v1
        operation = UUID(operation_id)
        if operation.version != 4 or str(operation) != operation_id:
            raise ValueError("catalogue upgrade requires one canonical UUID4 operation")
        lifecycle = self.lifecycle
        lifecycle.core._require(credential, "d12_lifecycle_control", lifecycle.namespace)
        registered_source_registry_v1(self.registry, source_catalogue_hash)
        installation, cohort = self.files.read_registered_cohort_v2(target_cohort_ref)
        configuration = read_verified_configuration_cohort_v2(cohort)
        selected, source_cohort, source_configuration = self.files.read_selected_configuration_cohort_v2()
        require_declared_catalogue_cohort_transition_v1(source_cohort,cohort,source_configuration,configuration,
            source_catalogue_hash=source_catalogue_hash,target_catalogue_hash=self.registry.catalogue_hash)
        if (installation != lifecycle.installation_id
                or configuration['host_profile']['installation_policy']['catalogue_hash'] != self.registry.catalogue_hash):
            raise AuthorityUnavailable("registered target package and compiled target catalogue differ")
        context, storage = lifecycle._storage()
        observed = lifecycle.supervisor.read_current_host_state_v1()
        if not observed.stopped_and_drained:
            raise AuthorityUnavailable("catalogue conversion requires actual whole-Host retirement")
        graph_path = next(item['resolved_path'] for item in storage['members'] if item['role'] == 'graph')
        from dataclasses import asdict
        request = dict(namespace=asdict(lifecycle.namespace_id), authority_namespace=lifecycle.namespace, installation_id=lifecycle.installation_id,
            operation_id=operation_id, pause_operation_id=pause_operation_id,
            target_cohort_ref=target_cohort_ref, target_cohort_digest=cohort.cohort_digest,
            source_catalogue_hash=source_catalogue_hash, target_catalogue_hash=self.registry.catalogue_hash,
            target_manifest_digest=cohort.package.manifest_sha256, actor=actor, storage=storage,
            selected_pointer=asdict(selected))
        request_digest = _digest(request)
        # Persist the exclusion BEFORE the independently committed Graph batch.
        # A crash afterwards leaves a resumable operation and blocks Host resume.
        with lifecycle.fences._frozen() as (db, deletion, execution, _):
            pause, head = self._admit(db, context, storage, pause_operation_id, actor, session_token, session_request)
            prior = db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                               (lifecycle.namespace, operation_id)).fetchone()
            if prior is None:
                require_catalogue_operation_unconsumed_in_tx_v1(db, lifecycle.namespace, operation_id)
                require_no_pending_catalogue_upgrade_in_tx_v1(db, lifecycle.namespace)
                lifecycle._constraints_in_tx(db, deletion, execution, storage, qualified_context=context)
                db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)",
                    (lifecycle.namespace, operation_id, request_digest, pause_operation_id, target_cohort_ref,
                     source_catalogue_hash, self.registry.catalogue_hash, cohort.package.manifest_sha256,
                     canonical_json(storage), pause[9], time.time(), 'pending', canonical_json(request)))
            elif prior[2] != request_digest or prior[9] != pause[9]:
                raise AuthorityUnavailable("catalogue retry changes the frozen Owner request")
            elif prior[11] == 'completed':
                return self._reply(json.loads(prior[12]), selected, cohort)
        with lifecycle.fences._frozen() as (db, deletion, execution, _):
            self._admit(db, context, storage, pause_operation_id, actor, session_token, session_request)
            row = db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                             (lifecycle.namespace, operation_id)).fetchone()
            if row[2] != request_digest or row[8] != canonical_json(storage):
                raise AuthorityUnavailable("catalogue operation or qualified storage changed")
            lifecycle._constraints_in_tx(db, deletion, execution, storage, qualified_context=context)
            scope = _CatalogueBatchScopeV1(lifecycle.namespace_id, operation_id, request_digest,
                source_catalogue_hash, self.registry.catalogue_hash, cohort.package.manifest_sha256,
                row[10], str(Path(graph_path).resolve(strict=True)), self, threading.get_ident())
            self._issued = scope
            try:
                store = GraphStore.open_registered_catalogue_upgrade_v1(scope, self.registry)
                try:
                    context.require_current('business')
                    receipt = store.advance_registered_catalogue_upgrade_v1(scope)
                finally:
                    store.close()
            finally:
                self._issued = None
            db.execute(f"UPDATE {TABLE} SET state=?,receipt_json=? WHERE namespace=? AND operation_id=? AND request_digest=?",
                ('completed' if receipt['phase'] == 'completed' else 'pending', canonical_json(receipt),
                 lifecycle.namespace, operation_id, request_digest))
            return self._reply(receipt, selected, cohort)

    def _admit(self, db, context, storage, pause_id, actor, token, request):
        lifecycle = self.lifecycle
        pause = lifecycle._operation(db, pause_id)
        head = read_lifecycle_head_in_tx_v1(db, lifecycle.namespace)
        guard = lifecycle._owner_still_current(db, pause)
        lifecycle.status_service._current_session_in_tx(db, actor=actor, token=token,
            request=request, expected_head=guard.authorization_head)
        if (pause[3] != 'pause' or pause[13] != 'paused' or head is None
                or head.state != 'paused' or head.operation_id != pause_id
                or canonical_json(storage) != canonical_json(json.loads(pause[10]))
                or any(lifecycle._counts(db))):
            raise AuthorityUnavailable("catalogue conversion lacks the current drained pause original")
        context.require_current('business')
        return pause, head
