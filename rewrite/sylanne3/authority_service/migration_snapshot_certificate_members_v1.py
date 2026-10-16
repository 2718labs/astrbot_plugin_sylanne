"""Core-authenticated C09 certificate membership in an installed migration.

Only the installed snapshot verifier issues the private export proof. Signed
metadata is appended with source revocation and target activation in their Core
transactions; it carries no certificate body and grants no Graph content access.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import hmac
import json
from weakref import WeakKeyDictionary

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable

TABLE = 'authority_migration_snapshot_certificate_members_v1'
DDL = "CREATE TABLE authority_migration_snapshot_certificate_members_v1 (namespace TEXT NOT NULL, transfer_id TEXT NOT NULL, member_key TEXT NOT NULL, member_kind TEXT NOT NULL CHECK(member_kind IN ('source_set','certificate','activation_set')), certificate_schema TEXT, certificate_digest TEXT, original_digest TEXT NOT NULL, original_json TEXT NOT NULL, PRIMARY KEY(namespace,transfer_id,member_key)) STRICT"
INDEX_DDL = "CREATE UNIQUE INDEX authority_migration_snapshot_certificate_original_v1 ON authority_migration_snapshot_certificate_members_v1(namespace,transfer_id,certificate_schema,certificate_digest) WHERE member_kind='certificate'"
TRIGGER_DDLS = {f'{TABLE}_{action.lower()}_immutable': f"CREATE TRIGGER {TABLE}_{action.lower()}_immutable BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'migration certificate membership immutable'); END" for action in ('UPDATE','DELETE')}
MEMBER_DDLS_V1 = {TABLE: DDL}
MEMBER_INDEXES_V1 = {'authority_migration_snapshot_certificate_original_v1': INDEX_DDL}
MEMBER_TRIGGERS_V1 = TRIGGER_DDLS
_OBJECTS = {('table', TABLE): DDL, ('index', 'authority_migration_snapshot_certificate_original_v1'): INDEX_DDL, **{('trigger', key): value for key,value in TRIGGER_DDLS.items()}}
_SIGNING_DOMAIN = 'migration-snapshot-members.v1'
_SCHEMA = 'sylanne3.authority.migration_snapshot_certificate_members.v1'
_VERIFIER = 'sylanne3.authority_service.installed_migration_graph_proofs.InstalledSourceGraphProofV1'
_ISSUER = object()
_PROOFS = WeakKeyDictionary()

@dataclass(frozen=True, slots=True)
class MigrationSnapshotCertificateSourceV1:
    authority_id: str
    namespace: str
    namespace_id: NamespaceId
    transfer_id: str
    source_installation_id: str
    source_graph_path: str
    source_graph_file_identity: tuple[int, int]
    source_permit_token: str
    source_permit_digest: str
    source_permit_generation: int
    source_graph_incarnation: str
    source_graph_revision: int
    source_graph_epoch: int
    source_requirements_digest: str
    snapshot_format: str
    snapshot_digest: str
    closure_digest: str
    schema_digest: str
    catalogue_digest: str
    generating_verifier: str
    export_proof_digest: str

@dataclass(frozen=True, slots=True)
class MigrationSnapshotCertificateCellV1:
    certificate_table: str
    certificate_key_columns: tuple[str, ...]
    certificate_key: tuple[str, ...]
    certificate_column: str
    certificate_schema: str
    certificate_authority_id: str
    certificate_installation_id: str
    certificate_namespace: str
    operation_id: str
    maintenance_generation: int
    old_incarnation: str
    new_incarnation: str
    raw_byte_count: int
    raw_sha256: str
    certificate_digest: str
    certificate_issue_digest: str | None

@dataclass(frozen=True, slots=True)
class SignedMigrationSnapshotCertificateMemberV1(MigrationSnapshotCertificateSourceV1):
    certificate_table: str
    certificate_key_columns: tuple[str, ...]
    certificate_key: tuple[str, ...]
    certificate_column: str
    certificate_schema: str
    certificate_authority_id: str
    certificate_installation_id: str
    certificate_namespace: str
    operation_id: str
    maintenance_generation: int
    old_incarnation: str
    new_incarnation: str
    raw_byte_count: int
    raw_sha256: str
    certificate_digest: str
    certificate_issue_digest: str | None
    core_issue_digest: str
    core_issue_signature_commitment: str
    source_set_digest: str
    member_key: str
    member_index: int
    member_digest: str
    signature: str

@dataclass(frozen=True, slots=True)
class SignedMigrationSnapshotCertificateMemberSetV1(MigrationSnapshotCertificateSourceV1):
    member_count: int
    member_root: str
    set_digest: str
    signature: str

@dataclass(frozen=True, slots=True)
class SignedMigrationActivationCertificateMemberSetV1:
    authority_id: str
    namespace: str
    namespace_id: NamespaceId
    transfer_id: str
    source_set_digest: str
    source_set_signature_commitment: str
    member_count: int
    member_root: str
    source_installation_id: str
    source_graph_incarnation: str
    snapshot_digest: str
    closure_digest: str
    target_installation_id: str
    target_permit_token: str
    target_permit_digest: str
    target_generation: int
    new_graph_incarnation: str
    graph_commit_digest: str
    recovery_digest: str
    activation_receipt_digest: str
    activation_anchor_digest: str
    set_digest: str
    signature: str

class VerifiedMigrationSnapshotCertificateMembersV1:
    __slots__ = ('__weakref__',)
    def __init__(self, issuer, verifier, receipt, plan, permit, source, members):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('installed source snapshot issuer required')
        _PROOFS[self] = (verifier, receipt, plan, permit, source, members)


def _issue_verified_snapshot_certificate_members_v1(verifier, receipt, plan, permit, schema, catalogue, tables, source_path, source_file_identity):
    from .installed_migration_graph_proofs import InstalledSourceGraphProofV1
    if type(verifier) is not InstalledSourceGraphProofV1:
        raise AuthorityUnavailable('actual installed source snapshot verifier required')
    members = certificate_cells_from_verified_inventory_v1(tables, plan.namespace_id, plan.namespace)
    body = (receipt, plan, permit, schema, catalogue, members, _VERIFIER, source_path, source_file_identity)
    source = MigrationSnapshotCertificateSourceV1(
        receipt.requirements.authority_id, plan.namespace, plan.namespace_id,
        plan.transfer_id, plan.source_installation_id, source_path, source_file_identity, permit.token,
        canonical_digest(permit), permit.generation, receipt.graph_incarnation,
        receipt.graph_revision, receipt.graph_epoch, canonical_digest(receipt.requirements),
        receipt.snapshot_format, receipt.snapshot_digest, receipt.closure_digest,
        schema, catalogue, _VERIFIER, canonical_digest(body))
    return VerifiedMigrationSnapshotCertificateMembersV1(_ISSUER, verifier, receipt, plan, permit, source, members)


def _require_source_proof(proof, verifier, receipt, plan, permit):
    original = _PROOFS.get(proof) if type(proof) is VerifiedMigrationSnapshotCertificateMembersV1 else None
    if original is None or original[:4] != (verifier, receipt, plan, permit):
        raise AuthorityUnavailable('actual installed export membership proof differs')
    source=original[4]
    actual=verifier._path.stat()
    if str(verifier._path)!=source.source_graph_path or (actual.st_dev,actual.st_ino)!=source.source_graph_file_identity:
        raise AuthorityUnavailable("installed source snapshot path identity changed")
    return original[4:]


def _scalar(raw, pos):
    value, end = json.JSONDecoder().raw_decode(raw, pos)
    if type(value) in (dict,list) or canonical_serialize(value) != raw[pos:end]:
        raise AuthorityUnavailable('noncanonical certificate scalar')
    return value,end


def _walk(raw, start=0, *, digest=None, mode=None, spans=None):
    """Validate canonical JSON and hash typed V1 manifests without building vectors."""
    pos=start
    def emit(value):
        if digest is not None: digest.update(value.encode('ascii'))
    if raw[pos]=='{':
        emit('{');pos+=1;previous=None;first=True
        if mode in ('manifest','row'):
            typename = 'GraphTableDispositionManifestV1' if mode=='manifest' else 'GraphRowDispositionV1'
            emit(canonical_serialize('$type')+':'+canonical_serialize(__package__.rsplit('.',1)[0]+'.runtime.c09_storage_rebase_contract_v1.'+typename))
            first=False
        while raw[pos]!='}':
            key,end=_scalar(raw,pos)
            if type(key) is not str or (previous is not None and key<=previous) or raw[end]!=':':
                raise AuthorityUnavailable('certificate object keys differ')
            previous=key
            if not first:emit(',')
            first=False;emit(raw[pos:end]+':');pos=end+1;value_start=pos
            child_mode='manifests' if key=='table_manifests' else 'rows' if mode=='manifest' and key=='rows' else None
            pos=_walk(raw,pos,digest=digest,mode=child_mode)
            if spans is not None:spans[key]=(value_start,pos)
            if raw[pos]==',':
                pos+=1
                if raw[pos] in '}]':raise AuthorityUnavailable('certificate trailing separator differs')
            elif raw[pos]!='}':raise AuthorityUnavailable('certificate object separator differs')
            else:break
        emit('}');return pos+1
    if raw[pos]=='[':
        emit('[');pos+=1;first=True
        while raw[pos]!=']':
            if not first:emit(',')
            first=False
            pos=_walk(raw,pos,digest=digest,mode='manifest' if mode=='manifests' else 'row' if mode=='rows' else None)
            if raw[pos]==',':
                pos+=1
                if raw[pos] in '}]':raise AuthorityUnavailable('certificate trailing separator differs')
            elif raw[pos]!=']':raise AuthorityUnavailable('certificate array separator differs')
            else:break
        emit(']');return pos+1
    _,end=_scalar(raw,pos);emit(raw[pos:end]);return end


def _raw_ascii_digest(raw):
    digest=hashlib.sha256()
    for offset in range(0,len(raw),65536):digest.update(raw[offset:offset+65536].encode('ascii'))
    return digest.hexdigest()


def _v1_cell(raw, table, key, namespace):
    from ..runtime.c09_storage_rebase_contract_v1 import GraphErasureRebaseCertificateV1
    spans={}
    if _walk(raw,spans=spans)!=len(raw):raise AuthorityUnavailable('certificate canonical EOF differs')
    names=tuple(field.name for field in fields(GraphErasureRebaseCertificateV1))
    if set(spans)!=set(names):raise AuthorityUnavailable('certificate V1 fields differ')
    digest=hashlib.sha256();digest.update(b'[')
    for index,name in enumerate(name for name in names if name!='certificate_digest'):
        if index:digest.update(b',')
        start,end=spans[name]
        if _walk(raw,start,digest=digest,mode='manifests' if name=='table_manifests' else None)!=end:
            raise AuthorityUnavailable('certificate typed field differs')
    digest.update(b']')
    def value(name):
        start,end=spans[name];return json.loads(raw[start:end])
    if (value('certificate_digest')!=digest.hexdigest() or value('namespace')!=namespace
            or value('operation_id')!=key[2] or value('schema')!='sylanne3.graph.c09_erasure_rebase.v1'):
        raise AuthorityUnavailable('certificate V1 typed digest or namespace differs')
    return MigrationSnapshotCertificateCellV1(table,('bot','persona','operation_id'),key,'certificate_json',
        value('schema'),value('authority_id'),value('installation_id'),value('namespace'),key[2],value('maintenance_generation'),value('old_incarnation'),value('new_incarnation'),
        len(raw),_raw_ascii_digest(raw),digest.hexdigest(),None)


def certificate_cells_from_verified_inventory_v1(tables, namespace_id, namespace):
    """Extract metadata solely from the inventory already verified by the producer."""
    result=[]
    for table,columns,rows in tables:
        if table not in ('graph_c09_rebase_certificates_v1','graph_c09_rebase_certificates_v2'):continue
        for row in rows:
            key=tuple(row[columns.index(name)] for name in ('bot','persona','operation_id'))
            if key[:2]!=namespace_id.as_tuple:raise AuthorityUnavailable('certificate inventory namespace differs')
            raw=row[columns.index('certificate_json')]
            if table.endswith('_v1'):
                member=_v1_cell(raw,table,key,namespace)
            else:
                from ..runtime.c09_paged_capture_contract_v2 import GraphErasureRebaseCertificateV2,c09_paged_value_from_wire_v2,c09_paged_value_to_wire_v2,MAX_DESCRIPTOR_BYTES_V2
                if len(raw.encode('utf-8'))>MAX_DESCRIPTOR_BYTES_V2:raise AuthorityUnavailable('certificate V2 descriptor exceeds bound')
                certificate=c09_paged_value_from_wire_v2(json.loads(raw),GraphErasureRebaseCertificateV2)
                scope=certificate.candidate.scope
                if (canonical_serialize(c09_paged_value_to_wire_v2(certificate))!=raw
                        or scope.authority_namespace!=namespace or scope.operation_id!=key[2]
                        or tuple(json.loads(scope.graph_namespace))!=namespace_id.as_tuple):
                    raise AuthorityUnavailable('certificate V2 original identity differs')
                member=MigrationSnapshotCertificateCellV1(table,('bot','persona','operation_id'),key,'certificate_json',
                    certificate.schema,scope.authority_id,scope.installation_id,scope.authority_namespace,key[2],scope.maintenance_generation,certificate.candidate.old_incarnation,
                    certificate.candidate.new_incarnation,len(raw.encode('utf-8')),hashlib.sha256(raw.encode('utf-8')).hexdigest(),certificate.certificate_digest,row[columns.index('issue_digest')])
            result.append(member)
    return tuple(sorted(result,key=lambda value:(value.certificate_table,value.certificate_key)))


def install_migration_snapshot_certificate_members_schema_v1(db, *, create):
    existing=_objects(db)
    if not existing and create:
        for ddl in _OBJECTS.values():db.execute(ddl)
        existing=_objects(db)
    if existing and existing!=_OBJECTS:raise AuthorityUnavailable('migration membership schema differs')


def _objects(db):
    return {(kind,name):sql for kind,name,sql in db.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE name=? OR name=? OR name=? OR name=?",
        (TABLE,'authority_migration_snapshot_certificate_original_v1',f'{TABLE}_update_immutable',f'{TABLE}_delete_immutable'))}


def _require_schema(db):
    if not db.in_transaction or _objects(db)!=_OBJECTS:
        raise AuthorityUnavailable('missing_authenticated_import_root_membership')


def _key(core):
    installed=core._c09_maintenance_authority_v1
    if installed is None:raise AuthorityUnavailable('actual installed migration membership signer absent; HOLD')
    return installed[0]


def _body_digest(kind, values):
    return canonical_digest((_SCHEMA,kind,values))


def _signature(core,kind,digest):
    return hmac.new(_key(core),(_SIGNING_DOMAIN+'\n'+_SCHEMA+'\n'+kind+'\n'+digest).encode(),hashlib.sha256).hexdigest()


def _append(core,db,kind,key,value):
    _require_schema(db)
    raw=canonical_serialize({'schema':_SCHEMA,'kind':kind,'value':asdict(value)})
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?)',
        (value.namespace,value.transfer_id,key,kind,
         value.certificate_schema if kind=='certificate' else None,
         value.certificate_digest if kind=='certificate' else None,canonical_digest(raw),raw))


def persist_snapshot_certificate_members_in_tx_v1(core,db,proof,verifier,receipt,plan,permit):
    source,cells=_require_source_proof(proof,verifier,receipt,plan,permit)
    if (source.authority_id!=core._anchor(db,plan.namespace,core._row(db,plan.namespace)).authority_id
            or source.source_installation_id!=_key_manifest(core).installation_id
            or source.namespace!=_key_manifest(core).namespace):
        raise AuthorityUnavailable('installed source membership signer identity differs')
    members=[]
    for cell in cells:
        if cell.certificate_table.endswith('_v1'):
            from .c09_graph_rebase_issue_v1 import read_graph_rebase_issue_original_v1,verify_graph_rebase_issue_signature_v1
            issue=read_graph_rebase_issue_original_v1(db,plan.namespace,cell.operation_id)
            if issue is None:raise AuthorityUnavailable('source certificate has no actual Core issue')
            verify_graph_rebase_issue_signature_v1(issue,_key(core))
            if (issue.authority_id!=source.authority_id or issue.namespace!=source.namespace
                    or issue.authority_id!=cell.certificate_authority_id
                    or issue.installation_id!=cell.certificate_installation_id
                    or issue.namespace!=cell.certificate_namespace
                    or issue.certificate_digest!=cell.certificate_digest or issue.operation_id!=cell.operation_id
                    or issue.maintenance_generation!=cell.maintenance_generation):
                raise AuthorityUnavailable('source certificate differs from authenticated Core issue')
        else:
            from .c09_graph_rebase_issue_v2 import _read_issue,_verify_signature
            issue=_read_issue(db,plan.namespace,cell.operation_id)
            if issue is None:raise AuthorityUnavailable('source certificate has no actual Core V2 issue')
            _verify_signature(issue,_key(core))
            scope=issue.certificate.candidate.scope
            if (cell.certificate_issue_digest!=issue.issue_digest
                    or issue.certificate.certificate_digest!=cell.certificate_digest
                    or scope.authority_id!=source.authority_id or scope.authority_namespace!=source.namespace
                    or scope.authority_id!=cell.certificate_authority_id
                    or scope.installation_id!=cell.certificate_installation_id
                    or scope.authority_namespace!=cell.certificate_namespace
                    or issue.certificate.candidate.old_incarnation!=cell.old_incarnation
                    or issue.certificate.candidate.new_incarnation!=cell.new_incarnation
                    or scope.operation_id!=cell.operation_id or scope.maintenance_generation!=cell.maintenance_generation):
                raise AuthorityUnavailable('source V2 certificate differs from authenticated Core issue')
        member_key=canonical_digest((cell.certificate_table,cell.certificate_key_columns,cell.certificate_key,cell.certificate_column))
        values={**asdict(source),**asdict(cell),'core_issue_digest':issue.issue_digest,
            'core_issue_signature_commitment':canonical_digest(issue.signature),'member_key':member_key}
        values['namespace_id']=source.namespace_id
        members.append((member_key,values))
    members.sort(key=lambda member:member[0])
    members=[(key,_body_digest('certificate_commitment', {**values,'member_index':index}),{**values,'member_index':index}) for index,(key,values) in enumerate(members,1)]
    if len({key for key,_,_ in members})!=len(members):raise AuthorityUnavailable('duplicate migration certificate member')
    root=_member_root(members)
    values={**asdict(source),'namespace_id':source.namespace_id,'member_count':len(members),'member_root':root}
    digest=_body_digest('source_set',values)
    original=SignedMigrationSnapshotCertificateMemberSetV1(**values,set_digest=digest,signature=_signature(core,'source_set',digest))
    _append(core,db,'source_set','source_set',original)
    signed=[]
    for member_key,member_digest,values in members:
        body={**values,'member_digest':member_digest,'source_set_digest':original.set_digest}
        member=SignedMigrationSnapshotCertificateMemberV1(**body,signature=_signature(core,'certificate',_body_digest('certificate',body)))
        _append(core,db,'certificate',member_key,member);signed.append(member)
    _PROOFS.pop(proof)
    return original,tuple(signed)


def _member_root(members):
    root=canonical_digest((_SCHEMA,'member_root',0))
    for index,(member_key,member_digest,*_) in enumerate(members,1):
        root=canonical_digest((_SCHEMA,'member_root',index,root,member_key,member_digest))
    return root


def _key_manifest(core):
    _key(core);return core._c09_maintenance_authority_v1[1]


def _decode(core,row,kind,cls):
    if row is None:return None
    raw=row[1]
    if canonical_digest(raw)!=row[0]:raise AuthorityUnavailable('migration membership original digest differs')
    payload=json.loads(raw)
    if set(payload)!= {'schema','kind','value'} or payload['schema']!=_SCHEMA or payload['kind']!=kind:
        raise AuthorityUnavailable('migration membership closed metadata differs')
    values=payload['value'];values['namespace_id']=NamespaceId(**values['namespace_id'])
    for name in ('certificate_key_columns','certificate_key','source_graph_file_identity'):
        if name in values:values[name]=tuple(values[name])
    value=cls(**values)
    manifest=_key_manifest(core)
    if (manifest.authority_id,manifest.namespace)!=(value.authority_id,value.namespace):
        raise AuthorityUnavailable('installed migration membership signer manifest differs; HOLD')
    if canonical_serialize({'schema':_SCHEMA,'kind':kind,'value':asdict(value)})!=raw:
        raise AuthorityUnavailable('migration membership canonical EOF differs')
    body={field.name:getattr(value,field.name) for field in fields(value) if field.name not in ('signature','member_digest','set_digest','source_set_digest')}
    if kind=='certificate':
        if value.member_digest!=_body_digest('certificate_commitment',body):
            raise AuthorityUnavailable('migration certificate member commitment differs')
        body={**body,'member_digest':value.member_digest,'source_set_digest':value.source_set_digest}
        digest=_body_digest('certificate',body)
    else:
        if kind=='activation_set':body['source_set_digest']=value.source_set_digest
        digest=value.set_digest
        if digest!=_body_digest(kind,body):raise AuthorityUnavailable('migration membership original commitment differs')
    if not hmac.compare_digest(value.signature,_signature(core,kind,digest)):
        raise AuthorityUnavailable('migration membership installed Core authentication differs')
    return value


def find_snapshot_certificate_member_set_in_tx_v1(core,db,namespace,transfer_id):
    if not db.in_transaction:raise AuthorityUnavailable("frozen migration membership transaction required")
    if not _objects(db):return None
    _require_schema(db)
    row=db.execute(f"SELECT original_digest,original_json FROM {TABLE} WHERE namespace=? AND transfer_id=? AND member_key='source_set' AND member_kind='source_set'",(namespace,transfer_id)).fetchone()
    original=_decode(core,row,'source_set',SignedMigrationSnapshotCertificateMemberSetV1)
    if original is None:return None
    if (original.namespace,original.transfer_id)!=(namespace,transfer_id):raise AuthorityUnavailable('migration source set row identity differs')
    return original


def read_snapshot_certificate_member_set_in_tx_v1(core,db,namespace,transfer_id):
    original=find_snapshot_certificate_member_set_in_tx_v1(core,db,namespace,transfer_id)
    if original is None:raise AuthorityUnavailable('missing_authenticated_import_root_membership')
    return original


def read_snapshot_certificate_member_by_original_in_tx_v1(core,db,namespace,transfer_id,certificate_schema,certificate_digest):
    _require_schema(db)
    row=db.execute(f"SELECT original_digest,original_json FROM {TABLE} WHERE namespace=? AND transfer_id=? AND member_kind='certificate' AND certificate_schema=? AND certificate_digest=?",(namespace,transfer_id,certificate_schema,certificate_digest)).fetchone()
    member=_decode(core,row,'certificate',SignedMigrationSnapshotCertificateMemberV1)
    if member is not None and (member.namespace,member.transfer_id,member.certificate_schema,member.certificate_digest)!=(namespace,transfer_id,certificate_schema,certificate_digest):
        raise AuthorityUnavailable('migration certificate member index identity differs')
    if member is not None:
        source=read_snapshot_certificate_member_set_in_tx_v1(core,db,namespace,transfer_id)
        if not 1<=member.member_index<=source.member_count or member.source_set_digest!=source.set_digest or any(getattr(member,field.name)!=getattr(source,field.name) for field in fields(MigrationSnapshotCertificateSourceV1)):
            raise AuthorityUnavailable('migration indexed member differs from signed source set')
    return member


def read_snapshot_certificate_members_in_tx_v1(core,db,status):
    source=read_snapshot_certificate_member_set_in_tx_v1(core,db,status.plan.namespace,status.plan.transfer_id)
    if (source.snapshot_digest,source.closure_digest,source.source_permit_digest,source.source_requirements_digest,
            source.source_graph_incarnation,source.source_graph_revision,source.source_graph_epoch,source.namespace_id,
            source.source_installation_id)!=(status.source_snapshot.snapshot_digest,status.source_snapshot.closure_digest,
            canonical_digest(status.source_permit),canonical_digest(status.source_snapshot.requirements),
            status.source_snapshot.graph_incarnation,status.source_snapshot.graph_revision,status.source_snapshot.graph_epoch,
            status.plan.namespace_id,status.plan.source_installation_id):
        raise AuthorityUnavailable('migration source membership snapshot differs')
    members=[];last_key=''
    while True:
        row=db.execute(f"SELECT member_key,original_digest,original_json FROM {TABLE} WHERE namespace=? AND transfer_id=? AND member_kind='certificate' AND member_key>? ORDER BY member_key COLLATE BINARY LIMIT 1",(source.namespace,source.transfer_id,last_key)).fetchone()
        if row is None:break
        key=row[0];member=_decode(core,row[1:],'certificate',SignedMigrationSnapshotCertificateMemberV1)
        if member.member_key!=key or member.source_set_digest!=source.set_digest or member.member_index!=len(members)+1:
            raise AuthorityUnavailable('migration source membership member identity differs')
        if any(getattr(member,field.name)!=getattr(source,field.name) for field in fields(MigrationSnapshotCertificateSourceV1)):
            raise AuthorityUnavailable('migration certificate member source differs')
        members.append(member);last_key=key
    if source.member_count!=len(members) or source.member_root!=_member_root((member.member_key,member.member_digest) for member in members):
        raise AuthorityUnavailable('migration member set completeness differs')
    return source,tuple(members)


def persist_activation_certificate_members_in_tx_v1(core,db,status,held,permit,recovery,receipt):
    source,members=read_snapshot_certificate_members_in_tx_v1(core,db,status)
    if held.certificate_member_set_digest!=source.set_digest:raise AuthorityUnavailable('target held certificate membership changed')
    values=dict(authority_id=source.authority_id,namespace=source.namespace,namespace_id=source.namespace_id,
        transfer_id=source.transfer_id,source_set_digest=source.set_digest,source_set_signature_commitment=canonical_digest(source.signature),
        member_count=source.member_count,member_root=source.member_root,source_installation_id=source.source_installation_id,
        source_graph_incarnation=source.source_graph_incarnation,snapshot_digest=source.snapshot_digest,closure_digest=source.closure_digest,
        target_installation_id=recovery.target_installation_id,target_permit_token=permit.token,target_permit_digest=canonical_digest(permit),
        target_generation=permit.generation,new_graph_incarnation=recovery.new_graph_incarnation,graph_commit_digest=recovery.graph_commit_digest,
        recovery_digest=canonical_digest(recovery),activation_receipt_digest=canonical_digest(receipt),activation_anchor_digest=canonical_digest(receipt.after_anchor))
    digest=_body_digest('activation_set',values)
    original=SignedMigrationActivationCertificateMemberSetV1(**values,set_digest=digest,signature=_signature(core,'activation_set',digest))
    _append(core,db,'activation_set','activation_set',original)
    return original


def read_activation_certificate_members_in_tx_v1(core,db,namespace,transfer_id):
    _require_schema(db)
    row=db.execute(f"SELECT original_digest,original_json FROM {TABLE} WHERE namespace=? AND transfer_id=? AND member_key='activation_set' AND member_kind='activation_set'",(namespace,transfer_id)).fetchone()
    original=_decode(core,row,'activation_set',SignedMigrationActivationCertificateMemberSetV1)
    if original is None:raise AuthorityUnavailable('missing_authenticated_import_root_membership')
    if (original.namespace,original.transfer_id)!=(namespace,transfer_id):raise AuthorityUnavailable('migration activation membership row differs')
    return original


def validate_snapshot_certificate_member_row_v1(core,columns,row):
    """Authenticate an already captured metadata row without rereading a database."""
    expected=('namespace','transfer_id','member_key','member_kind','certificate_schema','certificate_digest','original_digest','original_json')
    if tuple(columns)!=expected or len(row)!=len(expected):
        raise AuthorityUnavailable('migration membership metadata columns differ')
    kind=row[3]
    cls={'source_set':SignedMigrationSnapshotCertificateMemberSetV1,
         'certificate':SignedMigrationSnapshotCertificateMemberV1,
         'activation_set':SignedMigrationActivationCertificateMemberSetV1}.get(kind)
    if cls is None:raise AuthorityUnavailable('migration membership metadata kind differs')
    original=_decode(core,row[6:],'certificate' if kind=='certificate' else kind,cls)
    key=original.member_key if kind=='certificate' else kind
    schema=original.certificate_schema if kind=='certificate' else None
    certificate_digest=original.certificate_digest if kind=='certificate' else None
    if row[:6]!=(original.namespace,original.transfer_id,key,kind,schema,certificate_digest):
        raise AuthorityUnavailable('migration membership signed metadata row identity differs')
    return original
