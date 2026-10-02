"""Independent authenticated Control-history conversion; V1 remains immutable.

Only the installed source producer signs history. Decoding a document supplies
neither a selector nor current rights. The V2 reader requires actual DISPOSED
selector state and independently rereads the selected files and full inventory.
"""
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from weakref import WeakValueDictionary

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .c09_control_inventory_export_v2 import (
    _identity, capture_control_inventory_export_v2, verify_control_inventory_export_v2,
)
from .c09_storage_control_v1 import file_observation_v1, _regular_path, ROLES
from ..runtime.c09_storage_rebase_contract_v1 import (
    SanitizedExecutionFactV4,SanitizedD02FactV4,SanitizedD11FactV4,SanitizedUnknownFactV4,
)
from ..runtime.c09_storage_transition_v1 import C09ExecutionBindingV1

SCHEMA = 'sylanne3.c09.sanitized-control-history.v2'
MAX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100000
FIELDS = frozenset(('schema','authority_commitment','installation_commitment','key_commitment',
    'control_commitment','generation','prior_selector_digest','source_inventory','source_inventory_digest',
    'old_control_files','current_manifest','storage_stage','frames','carrier_inventory',
    'writer_quiescence','history_digest','signature'))
FRAME_FIELDS = frozenset(('source_prepared_digest','source_signature_commitment','source_generation',
    'source_row_commitment','facts','bindings','association_digest'))
UNRESOLVED = frozenset(('graph_contact_owner_invocations_v3',))
LIFE_TABLES = ('graph_internal_life_content_originals_v1','graph_internal_life_worker_originals_v2','graph_internal_life_paid_originals_v2')


def _decode(raw, typ):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, typ)


def _known():
    from .c09_authority_storage_rebase import _KNOWN_CORE_TABLES, _KNOWN_DELETION_TABLES
    from ..runtime.c09_graph_rebase_candidate_v1 import _KNOWN
    return {'core':_KNOWN_CORE_TABLES,'deletion':_KNOWN_DELETION_TABLES,'graph':_KNOWN,
        'execution':frozenset(('authority_v2_execution_meta','authority_v2_execution_entries',
            'authority_v2_execution_redacted_prefix_v4'))}


def _factual_member_observation_v2(control, member):
    """Closed selected member under the real lease; never discard WAL data."""
    from .c09_storage_control_v1 import file_observation_v1
    control.lease.require_held()
    control.verify_member_v1(member, prepared=False)
    path = Path(member['resolved_path'])
    observations = {}
    for suffix in ('', '-wal', '-shm', '-journal'):
        candidate = Path(str(path) + suffix)
        if not os.path.lexists(candidate):
            observations[suffix] = None
            continue
        if suffix == '-journal':
            raise AuthorityUnavailable('C09 factual immutable open refuses a rollback journal; HOLD')
        value = file_observation_v1(candidate, exclusive=True)
        if suffix == '-wal' and value['prepared_size'] != 0:
            raise AuthorityUnavailable('C09 factual immutable open refuses nonempty WAL; HOLD')
        observations[suffix] = value
    if observations[''] is None:
        raise AuthorityUnavailable('C09 factual selected database is absent')
    control.lease.require_held()
    return observations


@contextmanager
def _history_member_connection_v2(control, member, *, closed_observation=None):
    path = Path(member['resolved_path'])
    if closed_observation is not None:
        if _factual_member_observation_v2(control, member) != closed_observation:
            raise AuthorityUnavailable('C09 factual member changed before immutable open')
        uri = path.as_uri() + '?mode=ro&immutable=1'
    else:
        uri = path.as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        yield db
    if closed_observation is not None and _factual_member_observation_v2(control, member) != closed_observation:
        raise AuthorityUnavailable('C09 factual member changed during immutable read')


def capture_history_carriers_v2(control, manifest, inventory, *, _closed_members=None):
    """Whole known SQL families plus actual registered external directories.

    Business files survive this Control conversion. Every row is committed;
    unresolved domain carriers and nonempty external snapshots remain HOLD.
    """
    from .c09_authority_storage_rebase import _objects, _columns, _row_commitment
    from .c09_surface_cleanup_v1 import _directory_files
    from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
    if type(inventory) is not InstallationFilesystemManifestV2 or (
            inventory.authority_id,inventory.installation_id,inventory.manifest_digest) != (
            control.authority_id,control.installation_id,manifest['inventory_manifest_digest']):
        raise AuthorityUnavailable('C09 V2 actual registered carrier manifest differs; HOLD')
    known = _known(); families = []; total = size = 0
    for member in manifest['members']:
        role = member['role']; control.verify_member_v1(member,prepared=False)
        with _history_member_connection_v2(control, member,
                closed_observation=None if _closed_members is None else _closed_members[member['role']]) as db:
            db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            objects = _objects(db)
            tables = {r[1] for r in objects if r[0]=='table'}
            if not tables <= known[role]:
                raise AuthorityUnavailable('C09 V2 unclassified complete carrier table; HOLD')
            for table in sorted(known[role]):
                rows = []; present = table in tables
                if present:
                    columns = _columns(db,table)
                    for row in db.execute(f'SELECT * FROM "{table}"'):
                        total += 1
                        size += sum(len(v) if isinstance(v,(str,bytes)) else 8 for v in row)
                        if total > MAX_ROWS or size > MAX_BYTES:
                            raise AuthorityUnavailable('C09 V2 complete carrier inventory exceeds bound; HOLD')
                        if table in UNRESOLVED:
                            raise AuthorityUnavailable('C09 V2 populated carrier has no authenticated disposal consumer: '+table+'; HOLD')
                        rows.append(_row_commitment(table,columns,tuple(row)))
                families.append(dict(role=role,table=table,present=present,
                    schema_commitment=canonical_digest(tuple(r for r in objects if r[2]==table)),
                    row_commitments=sorted(rows)))
    directories = []
    retained={m['resolved_path']+suffix for m in manifest['members']
        for suffix in ('','-wal','-shm','-journal')}
    for resource in inventory.resources:
        if resource.kind in {'controlled_backup','export','rebuild_temp','cache'}:
            if _directory_files(resource.path,protected=retained):
                raise AuthorityUnavailable('C09 V2 nonempty external carrier lacks complete sanitized disposition; HOLD')
            directories.append(dict(resource_id=resource.resource_id,path=resource.path,kind=resource.kind,state='empty_of_unselected_files'))
    return dict(schema='sylanne3.c09.complete-history-carriers.v2',
        installation_inventory=json.loads(canonical_serialize(asdict(inventory))),families=families,directories=directories)


def _verify_life_history_archives_v2(control, manifest, frames, *, _closed_members=None):
    """Authenticate the new retained family against every signed V2 fact frame.

    Missing-all differs from a signed empty inventory. Old histories whose
    closed family set predates this family are rejected by the normal verifier;
    no absent row is inserted and no old payload is re-signed here.
    """
    from .c09_life_completed_archive_v1 import (
        TABLE, INVENTORY_PREFIX, validate_life_archive_frame_v1,
        require_completed_life_archive_schema_v1, validate_selected_life_carriers_v1)
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked
    member = next(v for v in manifest['members'] if v['role']=='core')
    with _history_member_connection_v2(control, member,
            closed_observation=None if _closed_members is None else _closed_members[member['role']]) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        expected=set(); originals=[]
        for frame in frames:
            facts,_bindings=_frame_types(frame)
            original=validate_life_archive_frame_v1(db,control,facts)
            if original is not None:
                expected.add((facts.namespace,facts.operation_id)); originals.append(original)
                actual=read_execution_recovery_facts_v4_locked(db,facts.namespace,operation_id=facts.operation_id)
                if actual!=facts:
                    raise AuthorityUnavailable('C09 V2 Life archive actual Core facts differ from signed history; HOLD')
        present=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
        if present:
            require_completed_life_archive_schema_v1(db)
            actual=set(db.execute(f'SELECT namespace,operation_id FROM {TABLE}'))
            if actual!=expected:
                raise AuthorityUnavailable('C09 V2 Life archive/fact history inventory is incomplete; HOLD')
    if len(originals)>1:
        raise AuthorityUnavailable('C09 V2 subsequent audit-association deletion disposition unavailable; HOLD')
    graph=next(v for v in manifest['members'] if v['role']=='graph')
    with _history_member_connection_v2(control, graph,
            closed_observation=None if _closed_members is None else _closed_members[graph['role']]) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        if originals:
            validate_selected_life_carriers_v1(db,originals[0])
        else:
            for table in LIFE_TABLES:
                if (db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
                        and db.execute(f'SELECT 1 FROM {table} LIMIT 1').fetchone()):
                    raise AuthorityUnavailable('C09 V2 populated Life family lacks signed full inventory; HOLD')


def _frame_types(frame):
    from .c09_recovery_frame_v4 import C09RecoveryFactFrameV4
    from .c09_recovery_frame_v5 import C09RecoveryFactFrameV5
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedRecoveryFactsV4
    from ..runtime.c09_storage_transition_v1 import C09RecoveryBindingsV1
    kinds={typ.__dataclass_fields__['schema'].default:typ for typ in (
        C09RecoveryFactFrameV4,C09RecoveryFactFrameV5,SanitizedRecoveryFactsV4)}
    raw=frame['facts']; kind=kinds.get(raw.get('schema')) if type(raw) is dict else None
    if kind is None:raise AuthorityUnavailable('C09 V2 unregistered sanitized frame; HOLD')
    return _decode(raw,kind),_decode(frame['bindings'],C09RecoveryBindingsV1)


def _association(frame, source_digest):
    return canonical_digest((source_digest,tuple((k,frame[k]) for k in sorted(FRAME_FIELDS-{'association_digest'}))))


def verify_sanitized_history_v2(control, value):
    identity=_identity(control)
    if (type(value) is not dict or set(value)!=FIELDS or value['schema']!=SCHEMA
            or any(value[k]!=v for k,v in identity.items()) or type(value['generation']) is not int
            or value['generation']!=1 or value['prior_selector_digest'] is not None
            or value['storage_stage'] not in {'READY','RELEASED'}):
        raise AuthorityUnavailable('C09 V2 closed history identity/generation differs')
    source=verify_control_inventory_export_v2(control,value['source_inventory'])
    if source['inventory_digest']!=value['source_inventory_digest']:
        raise AuthorityUnavailable('C09 V2 source inventory association differs')
    control._manifest(value['current_manifest'])
    q=value['writer_quiescence'];control.verify_original_v1(q,'quiescence_digest')
    if (q.get('operation_id')!='control-history-v2:'+source['inventory_digest'][:40]
            or q.get('active_writers')!=0 or q.get('installation_id')!=control.installation_id
            or q.get('storage_generation')!=value['current_manifest']['generation']):
        raise AuthorityUnavailable('C09 V2 actual source writer quiescence differs')
    frames=value['frames']
    operations=next(f['row_commitments'] for f in source['families'] if f['table']=='c09_storage_operations_v1')
    if type(frames) is not list or len(frames)>1024 or len(frames)!=len(operations):
        raise AuthorityUnavailable('C09 V2 partial complete history; HOLD')
    prior=None; seen=[]
    for n,frame in enumerate(frames,1):
        if type(frame) is not dict or set(frame)!=FRAME_FIELDS or frame['source_generation']!=n:
            raise AuthorityUnavailable('C09 V2 closed frame/generation differs')
        facts,bindings=_frame_types(frame)
        if (bindings.facts_digest!=facts.facts_digest or bindings.prior_transition_digest_or_none!=prior
                or (bindings.authority_id,bindings.installation_id,bindings.namespace,bindings.operation_id)!=
                   (facts.authority_id,facts.installation_id,facts.namespace,facts.operation_id)
                or (facts.authority_id,facts.installation_id)!=(control.authority_id,control.installation_id)
                or frame['association_digest']!=_association(frame,source['inventory_digest'])):
            raise AuthorityUnavailable('C09 V2 full-old to sanitized-frame association differs')
        prior=frame['source_prepared_digest'];seen.append(frame['source_row_commitment'])
    if sorted(seen)!=operations or len(frames)!=value['current_manifest']['generation']:
        raise AuthorityUnavailable('C09 V2 omitted/duplicate source history; HOLD')
    carriers=value['carrier_inventory']
    if type(carriers) is not dict or set(carriers)!={'schema','installation_inventory','families','directories'}:
        raise AuthorityUnavailable('C09 V2 closed carrier inventory differs')
    from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
    inventory=_decode(carriers['installation_inventory'],InstallationFilesystemManifestV2)
    if carriers['schema']!='sylanne3.c09.complete-history-carriers.v2' or inventory.manifest_digest!=value['current_manifest']['inventory_manifest_digest']:
        raise AuthorityUnavailable('C09 V2 registered carrier digest differs')
    expected=[(role,table) for role in ROLES for table in sorted(_known()[role])]
    if (type(carriers['families']) is not list or len(carriers['families'])!=len(expected)
            or [(f.get('role'),f.get('table')) for f in carriers['families']]!=expected):
        raise AuthorityUnavailable('C09 V2 missing carrier family; HOLD')
    count=0
    for family in carriers['families']:
        if set(family)!={'role','table','present','schema_commitment','row_commitments'} or type(family['present']) is not bool:
            raise AuthorityUnavailable('C09 V2 closed carrier family differs')
        rows=family['row_commitments']
        if type(rows) is not list or rows!=sorted(set(rows)) or not family['present'] and rows:
            raise AuthorityUnavailable('C09 V2 exact carrier row inventory differs')
        if family['table'] in UNRESOLVED and rows:
            raise AuthorityUnavailable('C09 V2 populated unresolved carrier; HOLD')
        count+=len(rows)
        for commitment in (*rows,family['schema_commitment']):
            if type(commitment) is not str or len(commitment)!=64 or any(c not in '0123456789abcdef' for c in commitment):
                raise AuthorityUnavailable('C09 V2 exact opaque carrier commitment differs')
    if count>MAX_ROWS:raise AuthorityUnavailable('C09 V2 complete carriers exceed bound; HOLD')
    expected_dirs=[dict(resource_id=r.resource_id,path=r.path,kind=r.kind,state='empty_of_unselected_files')
        for r in inventory.resources if r.kind in {'controlled_backup','export','rebuild_temp','cache'}]
    if carriers['directories']!=expected_dirs:
        raise AuthorityUnavailable('C09 V2 missing external SnapshotStore carrier; HOLD')
    files=value['old_control_files']
    if type(files) is not list or not files or len(files)>4 or files[0]['resolved_path']!=str(control.path):
        raise AuthorityUnavailable('C09 V2 actual old Control inventory differs')
    paths=[f['resolved_path'] for f in files]
    if len(set(paths))!=len(paths) or not set(paths)<={str(control.path)+s for s in ('','-wal','-shm','-journal')}:
        raise AuthorityUnavailable('C09 V2 old Control companion inventory differs')
    body={k:v for k,v in value.items() if k not in {'history_digest','signature'}}
    committed=canonical_digest(body)
    expected=hmac.new(control._key,(SCHEMA+'\n'+committed).encode(),hashlib.sha256).hexdigest()
    if value['history_digest']!=committed or type(value['signature']) is not str or not hmac.compare_digest(expected,value['signature']):
        raise AuthorityUnavailable('C09 V2 independent history signature differs')
    return value


def read_sanitized_history_v2(control, path):
    path=_regular_path(path)
    with path.open('rb') as stream:data=stream.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:raise AuthorityUnavailable('C09 V2 complete history exceeds bound; HOLD')
    value=json.loads(data)
    if canonical_serialize(value).encode()!=data:
        raise AuthorityUnavailable('C09 V2 history is not exact canonical bytes')
    return verify_sanitized_history_v2(control,value)


def build_sanitized_history_v2(control,target_path,*,gate,inventory_manifest=None):
    from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
    from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
    if type(gate) is not InstalledC09WriterGateV1 or gate.control is not control:
        raise AuthorityUnavailable('C09 V2 actual installed writer gate required')
    source=capture_control_inventory_export_v2(control)
    operation='control-history-v2:'+source['inventory_digest'][:40]
    quiescence=gate.revoke_and_drain_v1(operation_id=operation)
    context,old_frames=InstalledSanitizedRecoveryResolverV4(storage_reader=control).read_verified_frames_v4()
    if context.stage not in {'READY','RELEASED'}:
        raise AuthorityUnavailable('C09 V2 source transition unfinished; HOLD')
    if old_frames:
        installed=_decode(old_frames[-1][0]['frozen_inventory_original'],InstallationFilesystemManifestV2)
        if inventory_manifest is not None and inventory_manifest!=installed:
            raise AuthorityUnavailable('C09 V2 supplied inventory differs from signed installed original')
        inventory_manifest=installed
    carriers=capture_history_carriers_v2(control,context.manifest,inventory_manifest)
    frames=[]
    with control._db() as db:
        columns=tuple(r[1] for r in db.execute('PRAGMA table_info(c09_storage_operations_v1)'))
        rows={r['prepared_digest']:tuple(r) for r in db.execute('SELECT * FROM c09_storage_operations_v1')}
    for original,facts,bindings in old_frames:
        frame=dict(source_prepared_digest=original['prepared_digest'],
            source_signature_commitment=canonical_digest(original['signature']),
            source_generation=original['maintenance_generation'],
            source_row_commitment=canonical_digest(('c09_storage_operations_v1',columns,rows[original['prepared_digest']])),
            facts=json.loads(canonical_serialize(asdict(facts))),bindings=json.loads(canonical_serialize(asdict(bindings))))
        frame['association_digest']=_association(frame,source['inventory_digest']);frames.append(frame)
    _verify_life_history_archives_v2(control, context.manifest, frames)
    if capture_control_inventory_export_v2(control)!=source:
        raise AuthorityUnavailable('C09 V2 source history changed during conversion; HOLD')
    # Source connections have all closed before final physical observations.
    files=[file_observation_v1(Path(str(control.path)+suffix),exclusive=True)
        for suffix in ('','-wal','-shm','-journal') if Path(str(control.path)+suffix).exists()]
    value=dict(schema=SCHEMA,**_identity(control),generation=1,prior_selector_digest=None,
        source_inventory=source,source_inventory_digest=source['inventory_digest'],old_control_files=files,
        current_manifest=context.manifest,storage_stage=context.stage,frames=frames,carrier_inventory=carriers,
        writer_quiescence=quiescence)
    value['history_digest']=canonical_digest(value)
    value['signature']=hmac.new(control._key,(SCHEMA+'\n'+value['history_digest']).encode(),hashlib.sha256).hexdigest()
    verify_sanitized_history_v2(control,value)
    target=_regular_path(target_path,exists=False)
    if target==control.path or any(target==Path(m['resolved_path']) for m in context.manifest['members']):
        raise AuthorityUnavailable('C09 V2 target overlaps current source')
    data=canonical_serialize(value).encode()
    if len(data)>MAX_BYTES:raise AuthorityUnavailable('C09 V2 complete history exceeds bound; HOLD')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return read_sanitized_history_v2(control,target)


@dataclass(frozen=True,slots=True)
class VerifiedStorageOpenContextV2:
    history_digest: str
    _manifest_json: str
    storage_generation: int
    storage_stage: str
    _reader: object
    _capability: object

    @property
    def manifest(self):
        return json.loads(self._manifest_json)

    def require_current(self,action='recovery'):
        self._reader.require_context_v2(self,action=action)


@dataclass(frozen=True,slots=True,weakref_slot=True)
class SanitizedExecutionEvidenceV2:
    namespace: str
    history_digest: str
    association_chain: tuple[str,...]
    fact: SanitizedExecutionFactV4
    binding: C09ExecutionBindingV1
    d02_facts: tuple[SanitizedD02FactV4,...]
    d11_facts: tuple[SanitizedD11FactV4,...]
    unknown: SanitizedUnknownFactV4 | None
    _context: VerifiedStorageOpenContextV2


class InstalledC09StorageReaderV2:
    def __init__(self,*,control,selector):
        from .c09_control_selector_v2 import InstalledC09ControlSelectorV2
        if type(selector) is not InstalledC09ControlSelectorV2 or selector.control is not control:
            raise AuthorityUnavailable('C09 V2 actual installed selector required')
        self.control,self.selector,self._capability=control,selector,object()
        self._evidence=WeakValueDictionary()

    def read_verified_current_storage_v2(self):
        selected=self.selector.current()
        history=read_sanitized_history_v2(self.control,selected['candidate_path'])
        if selected['history_digest']!=history['history_digest']:
            raise AuthorityUnavailable('C09 V2 selected history differs')
        from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
        inventory=_decode(history['carrier_inventory']['installation_inventory'],InstallationFilesystemManifestV2)
        # selector.current() already authenticated DISPOSED and retirement. Before
        # the first SQLite open, prove all selected members are static and contain
        # no pending WAL or rollback journal; never checkpoint factual inputs.
        closed = {m['role']:_factual_member_observation_v2(self.control, m)
            for m in history['current_manifest']['members']}
        actual=capture_history_carriers_v2(self.control,history['current_manifest'],inventory,
            _closed_members=closed)
        _verify_life_history_archives_v2(self.control,history['current_manifest'],history['frames'],
            _closed_members=closed)
        if any(_factual_member_observation_v2(self.control, m) != closed[m['role']]
                for m in history['current_manifest']['members']):
            raise AuthorityUnavailable('C09 factual cohort changed during authenticated read')
        if actual!=history['carrier_inventory']:
            raise AuthorityUnavailable('C09 V2 actual retained carrier changed; HOLD')
        return VerifiedStorageOpenContextV2(history['history_digest'],canonical_serialize(history['current_manifest']),
            history['current_manifest']['generation'],history['storage_stage'],self,self._capability)

    def require_context_v2(self,context,*,action='recovery'):
        if action not in {'recovery','maintenance'}:
            raise AuthorityUnavailable('C09 V2 business/accounting admission adapter unavailable; HOLD')
        if type(context) is not VerifiedStorageOpenContextV2 or context._reader is not self or context._capability is not self._capability:
            raise AuthorityUnavailable('C09 V2 actual context required')
        actual=self.read_verified_current_storage_v2()
        if (actual.history_digest,actual._manifest_json,actual.storage_generation,actual.storage_stage)!=(
                context.history_digest,context._manifest_json,context.storage_generation,context.storage_stage):
            raise AuthorityUnavailable('C09 V2 context is no longer selected')

    def read_verified_frames_v2(self):
        context=self.read_verified_current_storage_v2()
        history=read_sanitized_history_v2(self.control,self.selector.current()['candidate_path'])
        frames=tuple((frame['association_digest'],*_frame_types(frame)) for frame in history['frames'])
        context.require_current('recovery')
        return context,frames

    def read_sanitized_execution_v2(self,*,namespace,execution_id):
        """Issue only private factual recovery evidence, never a current grant."""
        context,frames=self.read_verified_frames_v2()
        if context.manifest['cohort_namespaces']!=[namespace]:
            raise AuthorityUnavailable('C09 V2 factual read crossed its installed namespace')
        found=binding=unknown=None
        d02={};d11={};chain=[]
        for association,facts,bindings in frames:
            if facts.namespace!=namespace:
                raise AuthorityUnavailable('C09 V2 historical namespace differs')
            chain.append(association)
            for fact in facts.executions:
                if fact.execution_id==execution_id:
                    if found is not None and found!=fact:raise AuthorityUnavailable('C09 V2 execution history conflict')
                    found=fact
            for item in bindings.execution_bindings:
                if item.execution_id==execution_id:
                    if binding is not None and binding!=item:raise AuthorityUnavailable('C09 V2 binding history conflict')
                    binding=item
            for fact in facts.unknown_facts:
                if fact.execution_id==execution_id:
                    if unknown is not None and unknown!=fact:raise AuthorityUnavailable('C09 V2 unknown obligation conflict')
                    unknown=fact
            for fact in facts.d02_facts:
                key=(fact.quote_id,fact.component_id,fact.outcome_id,fact.settlement_id)
                if key in d02 and d02[key]!=fact:raise AuthorityUnavailable('C09 V2 D02 obligation conflict')
                d02[key]=fact
            for fact in facts.d11_facts:
                key=(fact.parent_budget_id,fact.idempotency_id,fact.settlement_id)
                if key in d11 and d11[key]!=fact:raise AuthorityUnavailable('C09 V2 D11 obligation conflict')
                d11[key]=fact
        if found is None:
            if binding is not None or unknown is not None:raise AuthorityUnavailable('C09 V2 execution fact missing from complete history')
            return None
        if binding is None or binding.input_commitment!=found.input_commitment:
            raise AuthorityUnavailable('C09 V2 exact business binding absent')
        selected_d02=tuple(v for _,v in sorted(d02.items()) if v.quote_id in binding.d02_quote_ids or v.component_id in binding.d02_component_ids)
        selected_d11=tuple(v for _,v in sorted(d11.items()) if v.settlement_id in binding.d11_settlement_ids)
        # The binding independently commits both complete D02 identifier sets.
        # OR selection also catches a fact which crosses one of those sets;
        # filtering by AND would silently discard that inconsistent carrier.
        if ({v.quote_id for v in selected_d02}!=set(binding.d02_quote_ids)
                or {v.component_id for v in selected_d02}!=set(binding.d02_component_ids)
                or {v.settlement_id for v in selected_d11}!=set(binding.d11_settlement_ids)
                or (found.status=='unknown')!=(unknown is not None)):
            raise AuthorityUnavailable('C09 V2 complete factual obligations absent or inconsistent; HOLD')
        value=SanitizedExecutionEvidenceV2(namespace,context.history_digest,tuple(chain),found,binding,
            selected_d02,selected_d11,unknown,context)
        context.require_current('recovery')
        self._evidence[id(value)]=value
        return value

    def require_execution_evidence_v2(self,value):
        if type(value) is not SanitizedExecutionEvidenceV2 or self._evidence.get(id(value)) is not value:
            raise AuthorityUnavailable('C09 V2 caller DTO is not installed factual evidence')
        if value.history_digest!=value._context.history_digest:
            raise AuthorityUnavailable('C09 V2 factual history association differs')
        self.require_context_v2(value._context,action='recovery')
        return value
