"""Local Linux C09 admission from the independently installed Authority.

A root-owned Unix socket authenticates both OS processes. The caller cannot
supply a PID, generation or Graph path, and cannot upgrade its old admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from weakref import WeakKeyDictionary
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from ..diagnostic_channel_v1 import diagnostic_channel_v1
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.linux_installation_security_v1 import read_installed_json_v1
from ..authority_service.c09_process_identity_v1 import read_process_identity_v1


class InstalledHostStorageAdmissionTimeoutV1(TimeoutError):
    def __init__(self, *, stage, elapsed_ns, stage_elapsed_ns):
        super().__init__("C09 Host storage admission timed out")
        self.stage = stage
        self.elapsed_ns = elapsed_ns
        self.stage_elapsed_ns = stage_elapsed_ns

    def diagnostic_v1(self):
        return {"stage": self.stage, "elapsed_ns": self.elapsed_ns,
            "stage_elapsed_ns": self.stage_elapsed_ns}


@dataclass(frozen=True, slots=True)
class InstalledHostStorageAdmissionV1:
    installation_id: str
    authority_id: str
    pointer_version: int
    storage_generation: int
    manifest_digest: str
    graph_path: Path
    process_original: dict
    lifecycle_bootstrap: dict | None = None
    package_selection: object | None = None
    package_bootstrap: dict | None = None
    binding: object | None = None

    def require_current_process_v1(self):
        if self.binding is not None:self.binding._require_custody_v4()
        if read_process_identity_v1(os.getpid()) != self.process_original:
            raise AuthorityUnavailable("C09 Host admission belongs to another process")


def load_installed_host_storage_v1(profile_id, bundle):
    if os.name != "posix":
        return None
    profile_root = Path("/etc/sylanne/client/profiles") / profile_id
    path = profile_root / "c09-storage.json"
    if not path.exists():
        return None
    config = read_installed_json_v1(path, limit=8192)
    if (set(config) != {"schema", "socket_path", "installation_id", "authority_id", "host_uid"}
            or config["schema"] != "sylanne3.c09.host-storage-admission.v1"
            or config["installation_id"] != bundle.installation_policy.installation_id
            or config["authority_id"] != bundle.installation_policy.expected_authority_id
            or config["host_uid"] != os.geteuid() or os.geteuid() == 0):
        raise AuthorityUnavailable("C09 Host installation scope differs")
    endpoint = Path(config["socket_path"])
    if not endpoint.is_absolute():
        raise AuthorityUnavailable("C09 local socket path must be installed")
    # Protect every parent from endpoint replacement. Socket itself must be root
    # owned; peer credentials below recheck the actual connected server.
    for parent in (endpoint.parent, *endpoint.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AuthorityUnavailable("C09 local socket parent is unsafe")
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
        raise AuthorityUnavailable("C09 local admission socket is unsafe")
    started = stage_started = time.monotonic_ns()
    stage = "socket_create"
    try:
        channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            channel.settimeout(10)
            stage = "connect"; stage_started = time.monotonic_ns()
            channel.connect(str(endpoint))
            stage = "peer_identity"; stage_started = time.monotonic_ns()
            pid, uid, _gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid < 1:
                raise AuthorityUnavailable("C09 local Authority process is not privileged")
            stage = "request_serialization"; stage_started = time.monotonic_ns()
            request = {"schema": "sylanne3.c09.host-admission-request.v3", "profile_id": profile_id,
                "installation_id": config["installation_id"], "authority_id": config["authority_id"]}
            selected = getattr(bundle, 'package_selection', None)
            if selected is not None:
                from dataclasses import asdict
                request['package_selection'] = asdict(selected)
            stage = "send"; stage_started = time.monotonic_ns()
            channel.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            stage = "response_read"; stage_started = time.monotonic_ns()
            with channel.makefile("rb") as stream:
                raw = stream.readline(16385)
            stage = "response_bound"; stage_started = time.monotonic_ns()
            if len(raw) > 16384 or not raw.endswith(b"\n"):
                raise AuthorityUnavailable("C09 admission response exceeds limit")
        except BaseException:
            channel.close();raise
    except Exception as exc:
        observed = time.monotonic_ns()
        diagnostic = {"stage": stage, "elapsed_ns": observed - started,
            "stage_elapsed_ns": observed - stage_started, "exception_type": type(exc).__name__,
            "observed_wall_time_ns": time.time_ns()}
        diagnostic_channel_v1(__name__).error("Sylanne C09 Host storage admission failure metadata: " +
            json.dumps(diagnostic, separators=(",", ":")))
        if isinstance(exc, TimeoutError):
            raise InstalledHostStorageAdmissionTimeoutV1(stage=stage, elapsed_ns=observed - started,
                stage_elapsed_ns=observed - stage_started) from exc
        raise
    try:
        return _finish_host_storage_admission_v4(raw,channel,pid,profile_id,bundle,config,selected,endpoint)
    except BaseException:
        channel.close();raise


def _finish_host_storage_admission_v4(raw,channel,server_pid,profile_id,bundle,config,selected,endpoint):
    result = json.loads(raw)
    if result.get("status") != "admitted":
        raise AuthorityUnavailable("C09 current Host admission is unavailable")
    fields = {"schema", "status", "profile_id", "installation_id", "authority_id", "pointer_version",
              "storage_generation", "manifest_digest", "graph_path", "process_original", "lifecycle_bootstrap", "graph_storage_binding"}
    schema = 'sylanne3.c09.host-admission.v3'
    if selected is not None: fields.update({'package_selection','package_bootstrap'})
    if (set(result) != fields or result["schema"] != schema
            or result["profile_id"] != profile_id or result["installation_id"] != config["installation_id"]
            or result["authority_id"] != config["authority_id"]
            or type(result["pointer_version"]) is not int or result["pointer_version"] < 0
            or type(result["storage_generation"]) is not int or result["storage_generation"] < 0
            or len(result["manifest_digest"]) != 64):
        raise AuthorityUnavailable("C09 admission response identity differs")
    if selected is not None:
        from ..authority_service.d12_package_files_v2 import decode_package_selection_v2
        if decode_package_selection_v2(result['package_selection']) != selected:
            raise AuthorityUnavailable('independent Host admission selected cohort differs')
    bootstrap = result["lifecycle_bootstrap"]
    if bootstrap is not None:
        from uuid import UUID
        if (type(bootstrap) is not dict or set(bootstrap) != {"operation_id", "expected_epoch", "invocation_id"}
                or type(bootstrap["expected_epoch"]) is not int or bootstrap["expected_epoch"] < 1
                or type(bootstrap["invocation_id"]) is not str or len(bootstrap["invocation_id"]) != 32
                or any(c not in "0123456789abcdef" for c in bootstrap["invocation_id"])
                or str(UUID(bootstrap["operation_id"])) != bootstrap["operation_id"] or UUID(bootstrap["operation_id"]).version != 4):
            raise AuthorityUnavailable("exact resume bootstrap identity required")
    package_bootstrap=result.get('package_bootstrap')
    if package_bootstrap is not None:
        expected={'operation_id','maintenance_phase','lifecycle_epoch','package_epoch','selection_revision','cohort_digest',
            'selection_digest','process_original','invocation_id','state'}
        from uuid import UUID
        if (selected is None or bootstrap is not None or type(package_bootstrap) is not dict or set(package_bootstrap)!=expected
                or package_bootstrap['state']!='bootstrap_only'
                or package_bootstrap['maintenance_phase'] not in {'forward','rollback','abort_before_switch'}
                or package_bootstrap['maintenance_phase']!='abort_before_switch' and package_bootstrap['operation_id']!=selected.operation_id
                or package_bootstrap['package_epoch']!=selected.package_epoch or package_bootstrap['selection_revision']!=selected.revision
                or package_bootstrap['cohort_digest']!=selected.cohort_digest or package_bootstrap['selection_digest']!=selected.selection_digest
                or package_bootstrap['process_original']!=result['process_original']
                or type(package_bootstrap['lifecycle_epoch']) is not int or package_bootstrap['lifecycle_epoch']<1
                or type(package_bootstrap['invocation_id']) is not str or len(package_bootstrap['invocation_id'])!=32
                or any(c not in '0123456789abcdef' for c in package_bootstrap['invocation_id'])
                or UUID(package_bootstrap['operation_id']).version!=4):
            raise AuthorityUnavailable('exact current package bootstrap admission required')
    graph = Path(result["graph_path"])
    if not graph.is_absolute() or graph.is_symlink() or not graph.is_file():
        raise AuthorityUnavailable("C09 current Graph path is unavailable")
    wire=result['graph_storage_binding'];binding=None
    if wire is not None:
        original=_validate_host_graph_wire_v4(wire)
        server_original=read_process_identity_v1(server_pid)
        if (original['mode']!='production_root' or original['host_process_original']!=result['process_original']
                or original['authority_process_original']!=server_original
                or original['graph_member']['resolved_path']!=str(graph)
                or (original['profile_id'],original['authority_id'],original['installation_id'],
                    original['pointer_version'],original['storage_generation'],original['manifest_digest'])!=
                   (profile_id,result['authority_id'],result['installation_id'],result['pointer_version'],
                    result['storage_generation'],result['manifest_digest'])):
            raise AuthorityUnavailable('actual Unix Host Graph binding differs from its authenticated admission')
        channel.setblocking(False)
        custody=_UnixHostGraphCustodyV4(channel=channel,server_original=server_original,endpoint=endpoint,bundle=bundle)
        binding=VerifiedHostGraphStorageBindingV4(_HOST_GRAPH_ISSUER_V4,wire=wire,custody=custody,
            bundle=bundle,profile_id=profile_id)
    else:channel.close()
    admission = InstalledHostStorageAdmissionV1(result["installation_id"], result["authority_id"],
        result["pointer_version"], result["storage_generation"], result["manifest_digest"],
        graph, result["process_original"], bootstrap, selected, package_bootstrap,binding)
    admission.require_current_process_v1()
    return admission


def require_current_selected_host_admission_v2(admission, bundle, package_root):
    """Actual Unix-admitted current process plus independently reread selection."""
    if type(admission) is not InstalledHostStorageAdmissionV1:
        raise AuthorityUnavailable('actual installed Host storage admission required')
    admission.require_current_process_v1()
    from .selected_profile_cohort_v2 import require_current_bundle_selection_v2
    selected = require_current_bundle_selection_v2(bundle, package_root, require_selected_python=True)
    if selected is None or admission.package_selection != selected:
        raise AuthorityUnavailable('actual Host admission has no matching current selected cohort')
    return selected


_HOST_GRAPH_ISSUER_V4=object()
_HOST_GRAPH_BINDINGS_V4=WeakKeyDictionary()
_HOST_GRAPH_WIRE_FIELDS_V4=frozenset(('schema','mode','authority_id','installation_id','namespace',
    'authority_namespace','profile_id','peer','host_process_original','host_invocation_id',
    'authority_process_original','admission_digest','gate_epoch','selection_kind','pointer_version',
    'storage_generation','manifest_digest','graph_member','graph_layout','initial_genesis_digest',
    'initial_plan_digest','selected_prepared_digest','selected_applied_digest','capture_scope_digest',
    'selection_digest','binding_nonce','binding_digest','admission_basis_kind','certificate_digest'))


def _validate_host_graph_wire_v4(value):
    from ..runtime_contracts import NamespaceId,namespace_ref,canonical_digest
    from ..segmented_sql_cell_v1 import LAYOUTS,LAYOUT_SCHEMA_DIGEST
    if (type(value)is not dict or set(value)!=_HOST_GRAPH_WIRE_FIELDS_V4
            or value['schema']!='sylanne3.c09.host-graph-storage-binding.v4'
            or value['mode']not in ('production_root','controlled_sdk_bootstrap','controlled_sdk_business_custody')
            or value['selection_kind']not in ('initial_segmented_v4','selected_v3')
            or type(value['namespace'])is not list or len(value['namespace'])!=2
            or namespace_ref(NamespaceId(*value['namespace']))!=value['authority_namespace']
            or type(value['peer'])is not list or len(value['peer'])!=2 or value['peer'][1]!=value['profile_id']
            or any(type(value[k])is not int or value[k]<0 for k in ('pointer_version','storage_generation'))
            or value['mode']=='production_root'and(type(value['gate_epoch'])is not int or value['gate_epoch']<0)
            or value['mode']=='controlled_sdk_bootstrap'and(value['gate_epoch']is not None or value['admission_basis_kind']!='root_held_census_v3')
            or value['mode']in ('production_root','controlled_sdk_business_custody')and(
                type(value['gate_epoch'])is not int or value['gate_epoch']<0 or value['admission_basis_kind']!='writer_peer_admission_v3')):
        raise AuthorityUnavailable('closed Host Graph storage binding identity differs')
    member,layout=value['graph_member'],value['graph_layout']
    if (type(member)is not dict or set(member)!={'role','resolved_path','device','file_id','incarnation_or_journal_id'}
            or member['role']!='graph' or not Path(member['resolved_path']).is_absolute()
            or type(layout)is not dict or set(layout)!={'layout_id','layout_schema_digest','storage_instance_id'}
            or layout['layout_id']!=LAYOUTS['graph'] or layout['layout_schema_digest']!=LAYOUT_SCHEMA_DIGEST):
        raise AuthorityUnavailable('closed actual Graph member/layout binding required')
    initial=value['selection_kind']=='initial_segmented_v4'
    if (initial and ((value['pointer_version'],value['storage_generation'])!=(0,0)
            or value['selected_prepared_digest']is not None or value['selected_applied_digest']is not None
            or value['capture_scope_digest']is not None or value['certificate_digest']is not None)
            or not initial and (value['initial_genesis_digest']is not None or value['initial_plan_digest']is not None)):
        raise AuthorityUnavailable('Host initial and selected origin domains differ')
    digests=('manifest_digest','selection_digest','admission_digest','binding_digest')+(
        ('initial_genesis_digest','initial_plan_digest')if initial else
        ('selected_prepared_digest','selected_applied_digest','capture_scope_digest','certificate_digest'))
    for key in digests:
        if type(value[key])is not str or len(value[key])!=64 or any(c not in '0123456789abcdef'for c in value[key]):
            raise AuthorityUnavailable('Host storage original digest differs: '+key)
    for key in ('host_process_original','authority_process_original'):
        original=value[key]
        if (type(original)is not dict or set(original)!={'pid','platform','birth'}
                or type(original['pid'])is not int or original['pid']<1
                or original['platform']!='linux' or type(original['birth'])is not str):
            raise AuthorityUnavailable('actual Host/Authority process birth required')
    if canonical_digest({k:v for k,v in value.items()if k!='binding_digest'})!=value['binding_digest']:
        raise AuthorityUnavailable('Host storage binding commitment differs')
    return value


class VerifiedHostGraphStorageBindingV4:
    """One authenticated live admission channel and one actual Graph database."""
    def __init__(self,issuer,*,wire,custody,bundle,profile_id):
        from ..runtime_contracts import NamespaceId
        if issuer is not _HOST_GRAPH_ISSUER_V4:
            raise AuthorityUnavailable('actual independent Host admission producer required')
        self.original=_validate_host_graph_wire_v4(wire)
        self.custody,self.bundle,self.profile_id=custody,bundle,profile_id
        self.namespace=NamespaceId(*wire['namespace']);self.authority_namespace=wire['authority_namespace']
        self.authority_id,self.installation_id=wire['authority_id'],wire['installation_id']
        self.selection_digest,self.origin_kind=wire['selection_digest'],wire['selection_kind']
        self.selection_kind=self.origin_kind;self.source_kind='host_graph_v4'
        self.certificate_digest=wire['certificate_digest']
        self.genesis_digest=wire['initial_genesis_digest'];self.capture_scope_digest=wire['capture_scope_digest']
        self.origin_scope_digest=wire['initial_plan_digest']if self.origin_kind=='initial_segmented_v4'else self.capture_scope_digest
        self.storage_instance_id=wire['graph_layout']['storage_instance_id']
        self.storage_generation=wire['storage_generation'];self.pointer_version=wire['pointer_version']
        self.manifest_digest=wire['manifest_digest'];self.db=None;self._closed=False
        _HOST_GRAPH_BINDINGS_V4[self]=self._identity_v4()
    def _identity_v4(self):
        from ..runtime_contracts import canonical_digest
        return (canonical_digest(self.original),self.custody,self.bundle,self.profile_id,self.db,self._closed,
            self.namespace,self.authority_namespace,self.authority_id,self.installation_id,self.selection_digest,
            self.origin_kind,self.selection_kind,self.source_kind,self.genesis_digest,self.capture_scope_digest,
            self.origin_scope_digest,self.storage_instance_id,self.storage_generation,self.pointer_version,self.manifest_digest,self.certificate_digest)
    def member(self,role):
        if role!='graph':raise AuthorityUnavailable('Host storage binding permits only its actual Graph role')
        return dict(self.original['graph_member'])
    def _require_custody_v4(self):
        if self._closed or _HOST_GRAPH_BINDINGS_V4.get(self)!=self._identity_v4():
            raise AuthorityUnavailable('actual Host Graph binding was closed or changed')
        self.custody.require_current_v4(binding=self)
        if read_process_identity_v1(os.getpid())!=self.original['host_process_original']:
            raise AuthorityUnavailable('Host Graph binding belongs to another actual process birth')
        policy=self.bundle.installation_policy
        if (policy.installation_id,policy.expected_authority_id,self.profile_id)!=(
                self.installation_id,self.authority_id,self.original['profile_id']):
            raise AuthorityUnavailable('actual Host installation bundle changed')
        member=self.member('graph');path=Path(member['resolved_path'])
        if path.is_symlink() or (path.stat().st_dev,path.stat().st_ino)!=(member['device'],member['file_id']):
            raise AuthorityUnavailable('actual admitted Graph file identity changed')
        return self
    def bind_database_v4(self,db,*,meter):
        if self.db is not None:raise AuthorityUnavailable('Host storage binding already owns its actual database')
        self._require_custody_v4()
        self.db=db;_HOST_GRAPH_BINDINGS_V4[self]=self._identity_v4()
        return self.require_current(db=db,meter=meter)
    def require_current(self,*,db,meter):
        from ..authority_service.c09_selected_history_v3 import _bounded
        from ..segmented_sql_cell_v1 import DDLS,TRIGGERS,LAYOUTS,LAYOUT_SCHEMA,LAYOUT_SCHEMA_DIGEST
        import sqlite3
        self._require_custody_v4()
        if db is not self.db or type(db)is not sqlite3.Connection:
            raise AuthorityUnavailable('Host runtime requires its one actual admitted Graph connection')
        b=_bounded(db,meter);rows=b.execute('PRAGMA database_list').fetchall()
        if (len(rows)!=1 or rows[0][1]!='main'
                or Path(rows[0][2]).resolve(strict=True)!=Path(self.member('graph')['resolved_path']).resolve(strict=True)):
            raise AuthorityUnavailable('Host database differs from its actual admitted Graph file')
        origin=self.original['initial_plan_digest']if self.origin_kind=='initial_segmented_v4'else self.capture_scope_digest
        expected=(1,LAYOUT_SCHEMA,self.storage_instance_id,'graph',LAYOUTS['graph'],LAYOUT_SCHEMA_DIGEST,
            self.authority_id,self.authority_namespace,self.installation_id,self.storage_generation,origin)
        if b.execute('SELECT * FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()!=expected:
            raise AuthorityUnavailable('Host actual Graph layout/origin header changed')
        for name,ddl in {**DDLS,**TRIGGERS}.items():
            kind='table'if name in DDLS else'trigger'
            if b.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone()!=(ddl,):
                raise AuthorityUnavailable('Host actual immutable Graph cell schema differs: '+name)
        return self
    def require_business_v4(self):
        self._require_custody_v4()
        if self.original['mode']not in ('production_root','controlled_sdk_business_custody'):
            raise AuthorityUnavailable('SDK bootstrap storage binding has no actual writer/business admission')
        return self
    def close_v4(self):
        if not self._closed:
            self._closed=True;_HOST_GRAPH_BINDINGS_V4.pop(self,None);self.custody.close_v4()


class _UnixHostGraphCustodyV4:
    def __init__(self,*,channel,server_original,endpoint,bundle):
        self.channel,self.server_original,self.endpoint,self.bundle=channel,server_original,endpoint,bundle
        self.closed=False
    def require_current_v4(self,*,binding):
        import select
        if self.closed or self.channel.fileno()<0 or read_process_identity_v1(self.server_original['pid'])!=self.server_original:
            raise AuthorityUnavailable('actual independent Host admission channel ended')
        if select.select((self.channel,),(),(),0)[0]:
            raise AuthorityUnavailable('actual Host storage custody was revoked or disconnected')
        if getattr(self.bundle,'package_selection',None)is not None:
            from .selected_profile_cohort_v2 import require_current_bundle_selection_v2
            require_current_bundle_selection_v2(self.bundle,Path(__file__).absolute().parents[3],require_selected_python=True)
    def close_v4(self):
        if not self.closed:
            self.closed=True;self.channel.close()


def read_root_controlled_sdk_host_graph_material_v4(*,assets,profile,root_census):
    """Root fixed-asset metadata producer; its DTO alone grants no Host access."""
    from contextlib import closing
    from uuid import uuid4
    import hashlib,hmac,sqlite3
    from ..runtime_contracts import NamespaceId,canonical_digest
    from ..authority_service.c09_storage_control_v1 import digest,canonical
    from ..authority_service.c09_storage_manifest_v2 import manifest_signature_domain
    from ..authority_service.c09_initial_segmented_genesis_v4 import (
        INITIAL_MANIFEST_SCHEMA_V4,require_initial_segmented_manifest_v4,_require_plan_v4,
        _require_compact_initial_empty_eof_v4,GENESIS_SCHEMA_V4,ROLES_V4)
    from ..authority_service.c09_storage_manifest_v3 import require_manifest_provenance_shape_v3
    from ..authority_service.linux_installation_security_v1 import require_linux_administrator_v1
    require_linux_administrator_v1()
    policy=profile['installation_policy'];namespace=NamespaceId(**policy['namespace'])
    if (assets['authority_id']!=policy['expected_authority_id']or assets['installation_id']!=policy['installation_id']
            or assets['namespace']!=policy['authority_namespace']
            or root_census['selection_scope']['authority_id']!=assets['authority_id']
            or root_census['selection_scope']['installation_id']!=assets['installation_id']):
        raise AuthorityUnavailable('Root Host graph producer fixed installation identity differs')
    key=Path(assets['key_path']).read_bytes()
    def verify(original,field):
        committed=digest({k:v for k,v in original.items()if k not in (field,'signature')})
        signature=hmac.new(key,(original['schema']+'\n'+committed).encode(),hashlib.sha256).hexdigest()
        if original.get('key_id')!=assets['key_id']or original.get(field)!=committed or not hmac.compare_digest(signature,original.get('signature','')):
            raise AuthorityUnavailable('Root Host graph actual Control original signature differs')
    with closing(sqlite3.connect(Path(assets['control_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None))as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        meta=dict(db.execute('SELECT key,value FROM c09_storage_meta_v1'))
        if any(meta[k]!=assets[k]for k in ('authority_id','installation_id','control_store_id','key_id')):
            raise AuthorityUnavailable('Root Host graph fixed Control identity differs')
        current=db.execute('SELECT pointer_version,current_manifest_digest,active_operation_id,stage,last_event_seq,last_event_digest '
            'FROM c09_storage_current_v1 WHERE installation_id=?',(assets['installation_id'],)).fetchone()
        if current is None:raise AuthorityUnavailable('Root Host graph current storage original is absent')
        stored=db.execute('SELECT manifest_json,key_id,signature FROM c09_storage_manifests_v1 WHERE manifest_digest=?',(current[1],)).fetchone()
        if stored is None or len(stored[0].encode())>262144:raise AuthorityUnavailable('bounded Root actual storage manifest required')
        manifest=json.loads(stored[0]);domain=manifest_signature_domain(manifest)
        body=dict(schema=domain,manifest=manifest,issuer_id=assets['authority_id'],key_id=assets['key_id'])
        if (stored[1]!=assets['key_id']or not hmac.compare_digest(stored[2],hmac.new(key,
                (domain+'\n'+digest(body)).encode(),hashlib.sha256).hexdigest())
                or manifest['manifest_digest']!=current[1]
                or manifest['authority_id']!=assets['authority_id']or manifest['installation_id']!=assets['installation_id']
                or manifest['cohort_namespaces']!=[assets['namespace']]):
            raise AuthorityUnavailable('Root Host graph current manifest signature differs')
        if manifest['schema']==INITIAL_MANIFEST_SCHEMA_V4:
            require_initial_segmented_manifest_v4(manifest)
            row=db.execute('SELECT genesis_json FROM c09_initial_segmented_genesis_v4 WHERE installation_id=?',(assets['installation_id'],)).fetchone()
            if row is None or len(row[0].encode())>262144:raise AuthorityUnavailable('Root actual initial genesis original required')
            original=json.loads(row[0]);verify(original,'genesis_digest');plan=_require_plan_v4(original['plan'])
            if (current!=(0,manifest['manifest_digest'],None,'READY',0,'genesis')
                    or manifest['initial_genesis_original_digest']!=original['genesis_digest']
                    or manifest['initial_genesis_plan_digest']!=plan['plan_digest']
                    or plan['authority_namespace']!=assets['namespace']or plan['namespace']!=policy['namespace']):
                raise AuthorityUnavailable('Root actual initial business storage selection differs')
            fields={'schema','authority_id','installation_id','control_store_id','namespace','authority_namespace','genesis_id',
                'plan','plan_digest','initial_origin_scope_digest','role_originals','empty_business_eof','empty_business_eof_digest',
                'core_counter_empty_eof','key_id','genesis_digest','signature'}
            if (set(original)!=fields or original['schema']!=GENESIS_SCHEMA_V4
                    or any(original[k]!=assets[k]for k in ('authority_id','installation_id','control_store_id'))
                    or original['plan_digest']!=plan['plan_digest']or original['initial_origin_scope_digest']!=plan['plan_digest']
                    or original['namespace']!=plan['namespace']or original['authority_namespace']!=plan['authority_namespace']
                    or original['genesis_id']!=plan['genesis_id']
                    or original['empty_business_eof_digest']!=canonical_digest(original['empty_business_eof'])
                    or manifest['empty_business_eof_digest']!=original['empty_business_eof_digest']):
                raise AuthorityUnavailable('Root Host initial signed original field domain differs')
            _require_compact_initial_empty_eof_v4(original,plan)
            for role in ROLES_V4:
                role_member=next(item for item in manifest['members']if item['role']==role)
                if (role_member!=original['role_originals'][role]['member']
                        or role_member['resolved_path']!=plan['role_paths'][role]
                        or manifest['segmented_layouts'][role]['storage_instance_id']!=plan['role_storage_instance_ids'][role]):
                    raise AuthorityUnavailable('Root Host initial signed plan/role instance differs')
            kind='initial_segmented_v4';genesis=original['genesis_digest'];initial_plan=plan['plan_digest']
            prepared_digest=applied_digest=capture=None
            selection=canonical_digest(('sylanne3.c09.initial-segmented-selection.v4',genesis,manifest['manifest_digest'],
                0,0,namespace,assets['authority_id'],assets['installation_id'],assets['control_store_id']))
        else:
            require_manifest_provenance_shape_v3(manifest)
            if current[3]!='RELEASED' or current[0]<1:raise AuthorityUnavailable('Root selected Host storage is not RELEASED')
            row=db.execute('SELECT prepared_original_json FROM c09_storage_operations_v3 WHERE operation_id=? AND new_manifest_digest=?',
                (current[2],current[1])).fetchone()
            event=db.execute('SELECT event_json FROM c09_storage_events_v1 WHERE installation_id=? AND event_seq=?',
                (assets['installation_id'],current[4])).fetchone()
            if row is None or event is None or max(len(row[0].encode()),len(event[0].encode()))>262144:
                raise AuthorityUnavailable('Root actual selected PREPARED/release original required')
            prepared=json.loads(row[0]);verify(prepared,'prepared_digest')
            final=json.loads(event[0]);verify(final,'event_digest');release=final['details']['release_original'];verify(release,'release_digest')
            if (final['event_digest']!=current[5]or final['stage']!='RELEASED'or final['operation_id']!=current[2]
                    or prepared['new_manifest_digest']!=current[1]or prepared['namespace']!=assets['namespace']
                    or prepared['authority_id']!=assets['authority_id']or prepared['installation_id']!=assets['installation_id']
                    or prepared['maintenance_generation']!=manifest['generation']
                    or prepared['expected_pointer_version']!=current[0]-1 or prepared['old_manifest_digest']!=manifest['prior_manifest_digest']
                    or release['manifest_digest']!=current[1]or release['operation_id']!=current[2]or release['state']!='applied'
                    or release['installation_id']!=assets['installation_id']or release['storage_generation']!=manifest['generation']):
                raise AuthorityUnavailable('Root selected actual signed source/release lineage differs')
            def build(kind,expected_digest=None):
                stored_original=db.execute('SELECT original_json,original_digest FROM c09_storage_build_originals_v1 '
                    'WHERE installation_id=? AND operation_id=? AND original_kind=?',(assets['installation_id'],current[2],kind)).fetchone()
                if stored_original is None or len(stored_original[0].encode())>262144:
                    raise AuthorityUnavailable('Root selected signed capture original is absent: '+kind)
                actual=json.loads(stored_original[0]);verify(actual,'original_digest')
                if (actual['installation_id']!=assets['installation_id']or actual['operation_id']!=current[2]
                        or actual['original_kind']!=kind or actual['original_digest']!=stored_original[1]
                        or canonical(actual)!=stored_original[0]or expected_digest is not None and actual['original_digest']!=expected_digest):
                    raise AuthorityUnavailable('Root selected signed capture original identity differs')
                return actual['details']
            from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
            capture_original=C09CaptureScopeV2(**build('capture_scope_v2'))
            issue=build('graph_issued_v2',prepared['graph_issue_original_digest'])
            mirror=build('graph_mirror_v2',prepared['graph_mirror_original_digest'])
            if (capture_original.scope_digest!=prepared['capture_scope_digest']
                    or capture_original.operation_id!=current[2]or capture_original.authority_namespace!=assets['namespace']
                    or issue['issue_digest']!=manifest['graph_issue_digest']
                    or mirror['graph_issue_digest']!=issue['issue_digest']
                    or mirror['certificate_digest']!=manifest['certificate_digest']or mirror['scope_digest']!=capture_original.scope_digest):
                raise AuthorityUnavailable('Root selected actual capture/certificate/mirror chain differs')
            kind='selected_v3';genesis=initial_plan=None;prepared_digest=prepared['prepared_digest']
            applied_digest=canonical_digest(release);capture=prepared['capture_scope_digest']
            selection=canonical_digest(('sylanne3.c09.selected-history-scope.v3',assets['authority_id'],assets['installation_id'],
                prepared['namespace'],current[0],manifest['manifest_digest'],manifest['generation'],prepared_digest))
        member=next(item for item in manifest['members']if item['role']=='graph')
        graph_member={k:member[k]for k in ('role','resolved_path','device','file_id','incarnation_or_journal_id')}
        path=Path(member['resolved_path']);info=path.stat()
        if path.is_symlink()or(info.st_dev,info.st_ino)!=(member['device'],member['file_id']):
            raise AuthorityUnavailable('Root actual Graph file identity differs from its signed selection')
        process=read_process_identity_v1(root_census['authority_process']['pid'])
        if process is None or process['birth']!=root_census['authority_process']['birth']:
            raise AuthorityUnavailable('Root actual SDK worker process birth differs')
        peer=assets['sdk_peer_descriptor']
        value=dict(schema='sylanne3.c09.host-graph-storage-binding.v4',mode='controlled_sdk_bootstrap',
            admission_basis_kind='root_held_census_v3',certificate_digest=None if kind=='initial_segmented_v4'else manifest['certificate_digest'],
            authority_id=assets['authority_id'],installation_id=assets['installation_id'],namespace=list(namespace.as_tuple),
            authority_namespace=assets['namespace'],profile_id=peer[1],peer=peer,host_process_original=process,
            host_invocation_id=root_census['hold_token'],authority_process_original=process,
            admission_digest=canonical_digest(root_census),gate_epoch=None,selection_kind=kind,pointer_version=current[0],
            storage_generation=manifest['generation'],manifest_digest=manifest['manifest_digest'],graph_member=graph_member,
            graph_layout=manifest['segmented_layouts']['graph'],initial_genesis_digest=genesis,initial_plan_digest=initial_plan,
            selected_prepared_digest=prepared_digest,selected_applied_digest=applied_digest,capture_scope_digest=capture,
            selection_digest=selection,binding_nonce=uuid4().hex)
        value['binding_digest']=canonical_digest(value)
        db.rollback()
        return _validate_host_graph_wire_v4(value)


_SDK_HOST_GRAPH_CUSTODIES_V4=WeakKeyDictionary()


class _ControlledSDKHostGraphCustodyV4:
    def __init__(self,issuer,*,census,daemon,wire,dormant):
        if issuer is not _HOST_GRAPH_ISSUER_V4:raise AuthorityUnavailable('actual SDK Root Host custody issuer required')
        self.census,self.daemon,self.dormant,self.wire=census,daemon,dormant,wire
        self.channel=census.channel;self.gate=daemon.c09_gate;self.epoch=self.gate._epoch
        self.closed=False;self.transferred=False;self.transfer_original=None;self.worker=None
    def require_current_v4(self,*,binding):
        from ..runtime_contracts import canonical_digest
        import select
        saved=_SDK_HOST_GRAPH_CUSTODIES_V4.get(self.census)
        if (self.closed or saved is None or saved()is not self or binding.custody is not self
                or self.channel.fileno()<0 or self.gate._operation is not None or self.gate._epoch!=self.epoch
                or canonical_digest(self.wire)!=canonical_digest(binding.original)
                or self.daemon._closed or select.select((self.channel,),(),(),0)[0]):
            raise AuthorityUnavailable('actual SDK Root Graph custody ended or changed')
        self.census.require_installed_cohort_v3()
        self.daemon.c09_control.lease.require_held()
        if self.transferred:
            if not self.census.closed or self.transfer_original is None:
                raise AuthorityUnavailable('SDK Graph custody has no actual Root mode transfer original')
        elif self.census.closed:
            raise AuthorityUnavailable('SDK startup census closed without actual Root custody transfer')
        if self.worker is not None:
            worker=self.worker()
            if worker is None or worker._closed or not worker._thread.is_alive():
                raise AuthorityUnavailable('SDK Graph custody lost its actual live GraphWorker')
    def bind_worker_v4(self,worker,binding):
        from ..graph_worker import GraphWorker
        from weakref import ref
        from threading import get_ident
        if (type(worker)is not GraphWorker or worker._thread.ident!=get_ident()or self.worker is not None
                or binding.custody is not self):
            raise AuthorityUnavailable('SDK Host binding requires its actual originating GraphWorker.call')
        self.worker=ref(worker)
    def revoke_v4(self):
        self.close_v4()
    def close_v4(self):
        if self.closed:return
        self.closed=True;self.gate.unregister_host_graph_custody_v4(self)
        _SDK_HOST_GRAPH_CUSTODIES_V4.pop(self.census,None)
        if self.transferred:self.channel.close()
    def promote_business_v4(self,binding,peer_admission):
        from ..runtime_contracts import canonical_digest,canonical_serialize
        if self.closed or not self.transferred or binding.custody is not self or self.wire['mode']!='controlled_sdk_bootstrap':
            raise AuthorityUnavailable('SDK business binding needs its exact transferred bootstrap custody')
        self.require_current_v4(binding=binding)
        peer=self.daemon.config.c09_maintenance_factory.peer
        self.daemon.c09_control.verify_original_v1(peer_admission,'admission_digest')
        if (self.gate._peer_admission_originals_v3.get(peer)!=peer_admission
                or peer_admission['process_original']!=binding.original['host_process_original']
                or peer_admission['manifest_digest']!=binding.manifest_digest or self.gate._epoch!=self.epoch):
            raise AuthorityUnavailable('SDK business custody lacks its actual signed current peer admission')
        request=dict(schema='sylanne.root-controlled-sdk-host-graph-request.v4',command='promote_host_graph_business_v4',
            held_request_digest=self.census.original['request_digest'],hold_token=self.census.original['hold_token'],
            binding_digest=self.wire['binding_digest'],peer_admission=peer_admission,gate_epoch=self.epoch)
        self.channel.sendall(canonical_serialize(request).encode());raw=self.channel.recv(16385)
        result=json.loads(raw)
        expected=dict(self.wire,mode='controlled_sdk_business_custody',admission_basis_kind='writer_peer_admission_v3',
            admission_digest=peer_admission['admission_digest'],gate_epoch=self.epoch)
        expected['binding_digest']=canonical_digest({k:v for k,v in expected.items()if k!='binding_digest'})
        if len(raw)>16384 or result!={'status':'host_graph_business_bound_v4','binding':expected}:
            self.close_v4();raise AuthorityUnavailable('Root did not confirm actual signed SDK business admission')
        self.wire=expected;binding.original=expected
        _HOST_GRAPH_BINDINGS_V4[binding]=binding._identity_v4()
        return binding.require_business_v4()
    def transfer_v4(self):
        from ..runtime_contracts import canonical_digest,canonical_serialize
        from uuid import uuid4
        if self.closed or self.transferred or self.worker is None or self.worker()is None:
            raise AuthorityUnavailable('actual live SDK worker is required for Root custody transfer')
        self.census.require_current()
        nonce=uuid4().hex
        request=dict(schema='sylanne.root-controlled-sdk-host-graph-request.v4',command='release_host_graph_custody_v4',
            held_request_digest=self.census.original['request_digest'],hold_token=self.census.original['hold_token'],
            binding_digest=self.wire['binding_digest'],transfer_nonce=nonce)
        self.channel.sendall(canonical_serialize(request).encode());raw=self.channel.recv(16385)
        result=json.loads(raw)
        expected=dict(schema='sylanne.root-controlled-sdk-host-graph-custody.v4',command='startup_released_host_custody_v4',
            process_census_digest=self.census.digest,descriptor_digest=self.census.descriptor.payload['descriptor_digest'],
            binding_digest=self.wire['binding_digest'],authority_process=self.census.original['authority_process'],
            app_cgroup=self.census.original['app_cgroup'],root_process=self.census.original['root_process'],
            run_deadline_monotonic_ns=self.census.original['run_deadline_monotonic_ns'],transfer_nonce=nonce,
            request_digest=self.census.original['request_digest'],hold_token=self.census.original['hold_token'],
            channel_nonce=self.census.original['channel_nonce'])
        if len(raw)>16384 or result!=expected:
            self.channel.close();self.closed=True
            raise AuthorityUnavailable('Root did not atomically release startup into exact SDK Host custody')
        self.transfer_original=result;self.transferred=True
        return result


def issue_fresh_controlled_sdk_host_graph_binding_v4(dormant):
    from ..runtime.d13_consumer_manifest_v3 import _FreshD13DormantCompositionV3
    from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKProcessCensusV3
    from ..runtime_contracts import canonical_serialize
    if type(dormant)is not _FreshD13DormantCompositionV3:
        raise AuthorityUnavailable('actual SDK dormant composition required for independent Root binding')
    dormant.require_v3();daemon=dormant.daemon;request=dormant.request
    q=request.activation.qualification;census=q.process_census
    if type(census)is not VerifiedControlledSDKProcessCensusV3 or census in _SDK_HOST_GRAPH_CUSTODIES_V4:
        raise AuthorityUnavailable('one actual independent SDK Root Graph custody required')
    return _issue_controlled_sdk_host_graph_binding_from_census_v4(census,daemon,dormant)


def _issue_controlled_sdk_host_graph_binding_from_census_v4(census,daemon,dormant):
    from ..runtime_contracts import canonical_serialize
    census.require_current()
    command=dict(schema='sylanne.root-controlled-sdk-host-graph-request.v4',command='host_graph_storage_binding_v4',
        held_request_digest=census.original['request_digest'],hold_token=census.original['hold_token'])
    census.channel.sendall(canonical_serialize(command).encode());raw=census.channel.recv(16385)
    result=json.loads(raw)
    if len(raw)>16384 or set(result)!={'status','binding'}or result['status']!='host_graph_storage_bound_v4':
        raise AuthorityUnavailable('actual Root SDK Graph storage binding reply required')
    wire=_validate_host_graph_wire_v4(result['binding'])
    peer=daemon.config.c09_maintenance_factory.peer
    bundles=tuple(item.installation_bundle for item in daemon.config.natural_model_authorities_v2.values()if item.observer_peer==peer)
    if len(bundles)!=1:raise AuthorityUnavailable('actual SDK Host bundle is absent or ambiguous')
    bundle=bundles[0]
    if (wire['mode']!='controlled_sdk_bootstrap'or wire['admission_digest']!=census.digest
            or wire['peer']!=list(peer)or wire['host_process_original']!=census.authority_process_original
            or wire['host_invocation_id']!=census.original['hold_token']):
        raise AuthorityUnavailable('Root SDK Graph binding crossed its exact current descriptor/census')
    custody=_ControlledSDKHostGraphCustodyV4(_HOST_GRAPH_ISSUER_V4,census=census,daemon=daemon,wire=wire,dormant=dormant)
    from weakref import ref
    _SDK_HOST_GRAPH_CUSTODIES_V4[census]=ref(custody)
    binding=VerifiedHostGraphStorageBindingV4(_HOST_GRAPH_ISSUER_V4,wire=wire,custody=custody,bundle=bundle,profile_id=peer[1])
    daemon.c09_gate.register_host_graph_custody_v4(custody)
    binding._require_custody_v4()
    return binding


def transfer_actual_controlled_sdk_host_graph_custody_v4(census):
    saved=_SDK_HOST_GRAPH_CUSTODIES_V4.get(census);custody=None if saved is None else saved()
    if custody is None or custody.closed:return None
    return custody.transfer_v4()


def verify_root_controlled_sdk_host_business_admission_v4(*,assets,profile,root_census,previous,peer_admission,gate_epoch):
    from contextlib import closing
    import sqlite3,hashlib,hmac
    from ..runtime_contracts import canonical_digest,canonical_serialize
    from ..authority_service.c09_storage_control_v1 import digest
    current=read_root_controlled_sdk_host_graph_material_v4(assets=assets,profile=profile,root_census=root_census)
    if any(current[k]!=v for k,v in previous.items()if k not in ('binding_nonce','binding_digest')):
        raise AuthorityUnavailable('Root SDK signed storage selection changed before business peer admission')
    key=Path(assets['key_path']).read_bytes()
    committed=digest({k:v for k,v in peer_admission.items()if k not in ('admission_digest','signature')})
    signature=hmac.new(key,(peer_admission['schema']+'\n'+committed).encode(),hashlib.sha256).hexdigest()
    if (peer_admission.get('schema')!='sylanne3.c09.writer-peer-admission.v3'
            or peer_admission.get('key_id')!=assets['key_id']or peer_admission.get('admission_digest')!=committed
            or not hmac.compare_digest(signature,peer_admission.get('signature',''))
            or peer_admission['authority_id']!=assets['authority_id']or peer_admission['installation_id']!=assets['installation_id']
            or peer_admission['namespace']!=assets['namespace']or peer_admission['peer']!=assets['sdk_peer_descriptor']
            or peer_admission['process_original']!=previous['host_process_original']
            or peer_admission['authority_process_original']!=previous['authority_process_original']
            or (peer_admission['manifest_digest'],peer_admission['pointer_version'],peer_admission['storage_generation'])!=
                (previous['manifest_digest'],previous['pointer_version'],previous['storage_generation'])):
        raise AuthorityUnavailable('Root SDK actual signed business peer admission differs')
    with closing(sqlite3.connect(Path(assets['control_path']).as_uri()+'?mode=ro',uri=True))as db:
        row=db.execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',(committed,)).fetchone()
        if row!=(canonical_serialize(peer_admission),):
            raise AuthorityUnavailable('Root SDK business admission was not actually committed by Control')
    result=dict(previous,mode='controlled_sdk_business_custody',admission_basis_kind='writer_peer_admission_v3',
        admission_digest=committed,gate_epoch=gate_epoch)
    result['binding_digest']=canonical_digest({k:v for k,v in result.items()if k!='binding_digest'})
    return _validate_host_graph_wire_v4(result)


def read_current_controlled_sdk_host_graph_binding_v4(*,daemon):
    """A new live Root metadata channel, independent of the released cold startup."""
    from ..authority_service.daemon import AuthorityDaemon
    from .c09_controlled_sdk_bootstrap_v3 import (VerifiedControlledSDKInstallerOriginalV3,
        read_controlled_sdk_root_descriptor_v3,hold_controlled_sdk_process_census_v3)
    from ..authority_service.d13_original_owner_v3 import require_actual_d13_core_birth_v4
    if type(daemon)is not AuthorityDaemon or daemon._closed or daemon.c09_gate._operation is not None:
        raise AuthorityUnavailable('actual current SDK daemon/selection required')
    q=daemon.c09_gate._controlled_sdk_activation_v3.qualification
    if type(q)is not VerifiedControlledSDKInstallerOriginalV3 or q.original is None or q.fresh_finalization is not None:
        raise AuthorityUnavailable('current SDK Host binding requires its genuine independent cold qualification')
    context=daemon.c09_control.read_verified_current_storage_v3();context.require_current('business')
    factory=daemon.config.c09_maintenance_factory
    from ..runtime_contracts import namespace_ref
    service=daemon.core._d13_cache_use_controls_v2[namespace_ref(factory.namespace)]
    birth=require_actual_d13_core_birth_v4(service)
    if birth.birth_profile!='controlled_sdk':raise AuthorityUnavailable('current SDK binding has another Core process profile')
    descriptor=read_controlled_sdk_root_descriptor_v3(q.descriptor.path,config=daemon.config,inventory=factory.inventory,peer=factory.peer)
    census=hold_controlled_sdk_process_census_v3(root_descriptor=descriptor,config=daemon.config,inventory=factory.inventory,peer=factory.peer)
    try:return _issue_controlled_sdk_host_graph_binding_from_census_v4(census,daemon,None)
    except BaseException:
        census.close();raise
