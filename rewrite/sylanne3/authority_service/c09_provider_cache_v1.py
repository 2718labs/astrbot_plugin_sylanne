"""Independently signed provider cache purge/read through a pinned adapter.

The adapter is an administrator-installed program, not a caller command. Its
provider signing key must be pinned separately. No Graph absence, HTTP success
or local file removal is accepted as evidence about provider-owned caches.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import canonical, digest
from .linux_installation_security_v1 import opened_installed_file_v1, read_installed_bytes_v1


class InstalledProviderCacheDispositionV1:
    def __init__(self, *, provider_id, executable=None, executable_sha256=None,
                 public_key_path=None, public_key_sha256=None, provider_config_digests=()):
        self.provider_id = provider_id
        self.executable, self.executable_sha256 = executable, executable_sha256
        self.public_key_path, self.public_key_sha256 = public_key_path, public_key_sha256
        if (type(provider_config_digests) not in {tuple, list}
                or tuple(provider_config_digests) != tuple(sorted(set(provider_config_digests)))
                or any(type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                    for value in provider_config_digests)):
            raise AuthorityUnavailable("provider cache exact historical configuration coverage required")
        self.provider_config_digests = tuple(provider_config_digests)
        if not isinstance(provider_id, str) or not provider_id:
            raise AuthorityUnavailable("installed provider cache identity required")
        if executable is not None:
            self._key()

    def require_historical_provider_scopes_v2(self, scopes):
        if (type(scopes) is not tuple or scopes != tuple(sorted(set(scopes)))
                or any(provider != self.provider_id or configuration not in self.provider_config_digests
                    for provider, configuration in scopes)):
            raise AuthorityUnavailable("provider cache historical configuration/account scope is unresolved")
        self._key()

    def _key(self):
        if self.executable is None or self.public_key_path is None:
            raise AuthorityUnavailable("provider cache purge/read adapter is not installed for " + self.provider_id)
        value = read_installed_bytes_v1(self.public_key_path, limit=32)
        if len(value) != 32 or hashlib.sha256(value).hexdigest() != self.public_key_sha256:
            raise AuthorityUnavailable("provider cache verification key pin differs")
        return value

    def _request(self, operation_id, control, action, receipt_id=None):
        context = control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if context.stage not in {"SWITCHED", "CLEANED"} or context.prepared_original["operation_id"] != operation_id:
            raise AuthorityUnavailable("provider cache operation is not current")
        inventory = control.read_build_original_v1(operation_id=operation_id, kind="provider_scope_inventory")
        if inventory is None:
            raise AuthorityUnavailable("provider cache complete frozen historical inventory absent")
        details = inventory["details"]
        if (set(details) != {"schema", "namespace", "installation_id", "provider_config_scopes", "source_row_commitments"}
                or details["schema"] != "sylanne3.c09.historical-provider-scopes.v2"
                or (details["namespace"], details["installation_id"]) != (context.prepared_original["namespace"], control.installation_id)):
            raise AuthorityUnavailable("provider cache historical inventory scope differs")
        scopes = tuple(tuple(item) for item in details["provider_config_scopes"])
        if scopes:
            self.require_historical_provider_scopes_v2(scopes)
        body = {"schema": "sylanne3.c09.provider-cache-request.v2" if scopes else "sylanne3.c09.provider-cache-request.v1", "action": action,
            "provider_id": self.provider_id, "installation_id": control.installation_id,
            "authority_id": control.authority_id, "namespace": context.prepared_original["namespace"],
            "operation_id": operation_id, "manifest_digest": context.manifest_digest,
            "scope": "installation_namespace_all_prompt_caches", "receipt_id": receipt_id}
        if scopes:
            body.update(scope="installation_namespace_exact_provider_config_prompt_caches",
                provider_config_scopes=scopes, scope_inventory_digest=inventory["original_digest"])
        return context, {**body, "request_digest": digest(body)}

    def _call(self, request):
        key = self._key()
        with opened_installed_file_v1(self.executable) as fd:
            with os.fdopen(os.dup(fd), "rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != self.executable_sha256:
                    raise AuthorityUnavailable("provider cache executable changed")
            # Keep the verified file descriptor open across exec; pathname
            # substitution cannot change which installed executable is run.
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
                result = subprocess.run([f"/proc/self/fd/{fd}"], input=canonical(request).encode(),
                    stdout=output, stderr=error, timeout=60, pass_fds=(fd,),
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/")
                if result.returncode != 0 or output.tell() > 1048576:
                    raise AuthorityUnavailable("provider cache adapter failed or exceeded response limit")
                output.seek(0)
                raw = output.read(1048577)
        try:
            envelope = json.loads(raw)
            if set(envelope) != {"payload", "signature"}:
                raise ValueError("provider envelope fields differ")
            payload = envelope["payload"]
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            v2 = request["schema"] == "sylanne3.c09.provider-cache-request.v2"
            schema = "sylanne3.c09.provider-cache-original.v2" if v2 else "sylanne3.c09.provider-cache-original.v1"
            Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(envelope["signature"], validate=True),
                schema.encode() + b"\0" + canonical(payload).encode())
            expected_fields = {"schema", "request_digest", "provider_id", "receipt_id", "state", "scope"}
            if v2:
                expected_fields |= {"provider_config_scopes", "scope_inventory_digest"}
            if (set(payload) != expected_fields
                    or payload["schema"] != schema
                    or payload["request_digest"] != request["request_digest"]
                    or payload["provider_id"] != self.provider_id
                    or payload["scope"] != request["scope"] or payload["state"] != "absent"
                    or not isinstance(payload["receipt_id"], str) or not payload["receipt_id"]
                    or request["receipt_id"] is not None and payload["receipt_id"] != request["receipt_id"]):
                raise ValueError("provider cache scope or result differs")
            if v2 and (payload["provider_config_scopes"] != json.loads(canonical(request["provider_config_scopes"]))
                    or payload["scope_inventory_digest"] != request["scope_inventory_digest"]):
                raise ValueError("provider cache did not attest every exact historical configuration scope")
        except Exception as exc:
            raise AuthorityUnavailable("provider cache signed original is invalid") from exc
        return envelope

    def advance_installed_surface_v3(self, *, operation_id, storage_reader, view, meter):
        progress=getattr(self,'_selected_provider_cleanup_v3',None)
        if progress is None:
            progress=InstalledProviderCacheCleanupV3(self,storage_reader,view,operation_id)
            self._selected_provider_cleanup_v3=progress
        elif progress.view is not view or progress.operation_id!=operation_id:
            raise AuthorityUnavailable('actual provider cleanup selection changed')
        return progress.advance(meter)

    def advance_installed_surface_reread_v3(self, *, operation_id, storage_reader, view, meter, original):
        progress=getattr(self,'_selected_provider_reread_v3',None)
        if progress is None:
            progress=InstalledProviderCacheCleanupV3(self,storage_reader,view,operation_id,saved_original=original)
            self._selected_provider_reread_v3=progress
        elif progress.view is not view or progress.operation_id!=operation_id or progress.saved_original!=original:
            raise AuthorityUnavailable('actual provider independent reread selection changed')
        return progress.advance(meter)

    def clean_installed_surface_v1(self, *, operation_id, storage_reader):
        control = storage_reader
        context, request = self._request(operation_id, control, "purge")
        plan = control.read_build_original_v1(operation_id=operation_id, kind="purge_model_prompt_caches")
        if plan is None:
            plan = control.record_cleanup_plan_v1(operation_id=operation_id, surface="model_prompt_caches",
                details={"provider_id": self.provider_id, "request": request,
                         "adapter_sha256": self.executable_sha256, "public_key_sha256": self.public_key_sha256})
        elif plan["details"]["request"] != request:
            raise AuthorityUnavailable("provider cache cleanup replay changed")
        original = self._call(request)
        _, read_request = self._request(operation_id, control, "read", original["payload"]["receipt_id"])
        reread = self._call(read_request)
        return control.sign_original_v1("sylanne3.c09.surface-evidence.v1", {
            "schema": "sylanne3.c09.surface-evidence.v1", "installation_id": control.installation_id,
            "issuer_id": control.authority_id, "operation_id": operation_id, "surface": "model_prompt_caches",
            "manifest_digest": context.manifest_digest, "action": "purged", "plan_digest": plan["original_digest"],
            "before_observations": [original], "after_observations": [{key: reread["payload"][key]
                for key in ("provider_id", "receipt_id", "state", "scope", *(
                    ("provider_config_scopes", "scope_inventory_digest") if "provider_config_scopes" in read_request else ()))}]},
            "evidence_digest")

    def reread_installed_surface_v1(self, *, operation_id, storage_reader, original):
        storage_reader.verify_original_v1(original, "evidence_digest")
        after = original["after_observations"]
        context, request = self._request(operation_id, storage_reader, "read", after[0]["receipt_id"])
        plan = storage_reader.read_build_original_v1(operation_id=operation_id, kind="purge_model_prompt_caches")
        if (original["operation_id"] != operation_id or original["manifest_digest"] != context.manifest_digest
                or original["surface"] != "model_prompt_caches" or plan is None
                or plan["original_digest"] != original["plan_digest"]):
            raise AuthorityUnavailable("provider cache current original changed")
        current = self._call(request)["payload"]
        expected = [{key: current[key] for key in ("provider_id", "receipt_id", "state", "scope", *(
            ("provider_config_scopes", "scope_inventory_digest") if "provider_config_scopes" in request else ()))}]
        if after != expected:
            raise AuthorityUnavailable("provider cache independent observation changed")
        return {"evidence_digest": original["evidence_digest"], "after_observations": after}


_SCOPE_DDL_V3='CREATE TABLE c09_provider_cleanup_scopes_v3 (selection_digest TEXT NOT NULL,scope_key TEXT NOT NULL,scope_json TEXT NOT NULL,scope_digest TEXT NOT NULL UNIQUE,PRIMARY KEY(selection_digest,scope_key)) STRICT'
_REQUEST_DDL_V3='CREATE TABLE c09_provider_cleanup_requests_v3 (selection_digest TEXT NOT NULL,scope_key TEXT NOT NULL,action TEXT NOT NULL,request_json TEXT NOT NULL,request_digest TEXT NOT NULL UNIQUE,PRIMARY KEY(selection_digest,scope_key,action)) STRICT'
_RESPONSE_DDL_V3='CREATE TABLE c09_provider_cleanup_responses_v3 (selection_digest TEXT NOT NULL,scope_key TEXT NOT NULL,action TEXT NOT NULL,response_json TEXT NOT NULL,response_digest TEXT NOT NULL UNIQUE,PRIMARY KEY(selection_digest,scope_key,action)) STRICT'


def require_provider_cleanup_schema_v3(control,db):
    for table,ddl in (('c09_provider_cleanup_scopes_v3',_SCOPE_DDL_V3),('c09_provider_cleanup_requests_v3',_REQUEST_DDL_V3),('c09_provider_cleanup_responses_v3',_RESPONSE_DDL_V3)):
        row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
        if row is None or row[0]!=ddl:raise AuthorityUnavailable('actual provider cache coverage schema differs')
        for action in ('UPDATE','DELETE'):
            row=db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(table+'_no_'+action.lower(),)).fetchone()
            if row is None or row[0]!=control._immutable_ddl(table,action):
                raise AuthorityUnavailable('actual provider cache coverage original is not immutable')


class _InstalledProviderAdapterWorkV3:
    """Pinned executable fragments, nonblocking child progress, bounded signed descriptor."""
    def __init__(self,service,request):
        self.service,self.request=service,request
        self.opened=opened_installed_file_v1(service.executable);self.fd=self.opened.__enter__()
        self.file=os.fdopen(os.dup(self.fd),'rb');self.initial=os.fstat(self.fd)
        self.hash=hashlib.sha256();self.process=None;self.raw=bytearray();self.eof=False;self.phase='pin';self.started=None
        self.result=None
    def close(self):
        if self.process is not None:
            if self.process.poll() is None:self.process.terminate()
            if self.process.stdout is not None:self.process.stdout.close()
        if self.file is not None:self.file.close();self.file=None
        if self.opened is not None:self.opened.__exit__(None,None,None);self.opened=None
    def advance(self,meter):
        from time import monotonic
        actual=os.fstat(self.fd)
        if (actual.st_dev,actual.st_ino,actual.st_size,actual.st_mtime_ns)!=(self.initial.st_dev,self.initial.st_ino,self.initial.st_size,self.initial.st_mtime_ns):
            raise AuthorityUnavailable('actual pinned provider adapter changed during its reserved work')
        if self.phase=='pin':
            meter.require_available(16384+1024)
            chunk=self.file.read(16384);meter.charge_read(len(chunk)+64)
            if chunk:self.hash.update(chunk);return False
            if self.hash.hexdigest()!=self.service.executable_sha256:
                raise AuthorityUnavailable('actual provider adapter executable pin differs')
            self.phase='start';return False
        if self.phase=='start':
            wire=canonical(self.request).encode();meter.charge_encode(len(wire))
            self.process=subprocess.Popen([f'/proc/self/fd/{self.fd}'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,pass_fds=(self.fd,),env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},cwd='/')
            self.process.stdin.write(wire);self.process.stdin.close()
            os.set_blocking(self.process.stdout.fileno(),False)
            self.started=monotonic();self.phase='output';return False
        if self.phase=='output':
            if monotonic()-self.started>60:
                raise AuthorityUnavailable('actual provider cache adapter exceeded its unchanged execution timeout')
            try:chunk=os.read(self.process.stdout.fileno(),16384)
            except BlockingIOError:chunk=None
            if chunk:
                meter.require_available(len(chunk)*4+len(self.raw));meter.charge_read(len(chunk))
                if len(self.raw)+len(chunk)>16384:
                    raise AuthorityUnavailable('actual provider singleton signed response exceeds its reserved descriptor bound')
                self.raw.extend(chunk);return False
            if chunk==b'':self.eof=True
            code=self.process.poll()
            if code is None or not self.eof:return False
            if code!=0:raise AuthorityUnavailable('actual pinned provider cache adapter failed')
            self.phase='verify';return False
        if self.phase=='verify':
            meter.require_available(len(self.raw)*7+4096)
            envelope=json.loads(self.raw);self.result=_verify_provider_envelope_v3(self.service,self.request,envelope,meter)
            self.close();self.phase='complete';return True
        return self.result is not None


def _verify_provider_envelope_v3(service,request,envelope,meter):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if set(envelope)!={'payload','signature'}:raise AuthorityUnavailable('actual provider signed envelope fields differ')
    key=service._key();meter.charge_read(32)
    payload=envelope['payload'];schema='sylanne3.c09.provider-cache-original.v2'
    fields={'schema','request_digest','provider_id','receipt_id','state','scope','provider_config_scopes','scope_inventory_digest'}
    if (set(payload)!=fields or payload['schema']!=schema or payload['request_digest']!=request['request_digest']
            or payload['provider_id']!=request['provider_id'] or payload['state']!='absent' or payload['scope']!=request['scope']
            or payload['provider_config_scopes']!=json.loads(canonical(request['provider_config_scopes']))
            or payload['scope_inventory_digest']!=request['scope_inventory_digest']
            or type(payload['receipt_id']) is not str or not payload['receipt_id']
            or request['receipt_id'] is not None and payload['receipt_id']!=request['receipt_id']):
        raise AuthorityUnavailable('actual provider signed absence scope or receipt differs')
    wire=schema.encode()+b'\0'+canonical(payload).encode();meter.charge_encode(len(wire))
    Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(envelope['signature'],validate=True),wire)
    return envelope


class InstalledProviderCacheCleanupV3:
    """Complete model/provider scope census, then one actual purge/read operation at a time."""
    def __init__(self,service,control,view,operation_id,*,saved_original=None):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if type(view) is not VerifiedSelectedHistoryReadV3 or view.basis.control is not control or view.basis.prepared['operation_id']!=operation_id:
            raise AuthorityUnavailable('actual selected provider cleanup composition required')
        self.service,self.control,self.view,self.operation_id=service,control,view,operation_id
        self.saved_original=saved_original;self.phase='schema';self.after='';self.model_count=0
        from .c09_provider_scope_v3 import _COMPLETE
        from ..runtime_contracts import canonical_digest
        self.model_root=canonical_digest((_COMPLETE,view.scope.scope_digest,view.completion.model_stream.complete.digest))
        self.scope_count=0;self.scope_root=canonical_digest(('sylanne3.c09.provider-cache-results.v3',view.basis.selection_digest))
        self.scope=self.request=self.work=self.purge=self.read=None
        self.original=self.failed=None
        control.register_c09_retained_state_v3(self)
    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        amount=16384
        for value in (self.scope,self.request,self.purge,self.read,self.saved_original,self.original):
            if value is not None:amount+=getsizeof(value)+sum(getsizeof(item) for item in value.values())
        if self.work is not None:amount+=getsizeof(self.work.raw)*8
        return amount

    def close(self):
        if self.work is not None:self.work.close();self.work=None
    def advance(self,meter):
        if self.failed is not None:raise AuthorityUnavailable(self.failed)
        try:return self._advance(meter)
        except BaseException as exc:self.failed=str(exc);self.close();raise
    def _advance(self,meter):
        from .c09_selected_history_v3 import _read_one,_bounded,record_selected_history_checkpoint_v3
        from .c09_provider_scope_v3 import read_provider_scope_for_model_v3
        from ..runtime_contracts import canonical_digest
        view,control,service=self.view,self.control,self.service
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        from .c09_maintenance_actor_v3 import InstalledC09MaintenanceActorV3
        import threading
        gate=control._final_gate_v3;maintenance=gate._installed_maintenance_v3
        actor=maintenance._maintenance_actor_v3
        if (type(maintenance) is not InstalledC09MaintenanceV1 or maintenance.control is not control
                or maintenance.surface_services['model_prompt_caches'] is not service or gate._operation!=self.operation_id
                or type(actor) is not InstalledC09MaintenanceActorV3 or actor.operation_id!=self.operation_id
                or actor.owner_thread!=threading.get_ident()):
            raise AuthorityUnavailable('actual same-actor registered delete composition required for provider cache disposal')
        maintenance.core._require(maintenance.credential,'delete',maintenance.closure.namespace)
        view.require_current(meter=meter)
        current=view.basis.require_current(meter=meter)
        if current['stage'] not in ('SWITCHED','CLEANED'):raise AuthorityUnavailable('actual provider cleanup stage changed')
        if self.original is not None:return dict(status='complete',phase='provider_cache_complete',original=self.original)
        if self.phase=='schema':
            with control._db(write=True) as db:
                for table,ddl in (('c09_provider_cleanup_scopes_v3',_SCOPE_DDL_V3),('c09_provider_cleanup_requests_v3',_REQUEST_DDL_V3),('c09_provider_cleanup_responses_v3',_RESPONSE_DDL_V3)):
                    present=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,),meter)
                    if present is None:
                        meter.write(db,ddl)
                        for action in ('UPDATE','DELETE'):meter.write(db,control._immutable_ddl(table,action))
                    elif present!=(ddl,):raise AuthorityUnavailable('actual provider cache coverage schema differs')
            self.phase='models'
        elif self.phase=='models':
            with view.basis.read_database('graph',meter=meter) as db:
                key=_read_one(db,'SELECT item_key FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1',
                    (view.scope.scope_digest,'model',self.after),meter)
            if key is None:
                complete=view.provider_scope_proof.details
                if (self.model_count,self.model_root)!=(complete['record_count'],complete['ordered_root']):
                    raise AuthorityUnavailable('actual prompt cache scope census omits historical model/provider originals')
                self.phase='scopes';self.after='';return dict(status='progress',phase='provider_model_scope_eof')
            model=view.lookup_model_original(key[0],meter=meter)
            original=read_provider_scope_for_model_v3(control,model,meter=meter);details=original['details']
            provider,cfg=details['provider_id'],details['provider_config_digest']
            if provider!=service.provider_id or cfg not in service.provider_config_digests:
                raise AuthorityUnavailable('actual installed cache adapter lacks this historical provider configuration scope')
            scope_key=canonical_digest((provider,cfg))
            with control._db(write=True) as db:
                prior=_bounded(db,meter).execute('SELECT scope_json FROM c09_provider_cleanup_scopes_v3 WHERE selection_digest=? AND scope_key=?',
                    (view.basis.selection_digest,scope_key)).fetchone()
                if prior is None:
                    scope=control.sign_original_v1('sylanne3.c09.provider-cache-scope.v3',dict(schema='sylanne3.c09.provider-cache-scope.v3',
                        selection_digest=view.basis.selection_digest,operation_id=self.operation_id,provider_id=provider,provider_config_digest=cfg,
                        source_provider_scope_original_digest=original['original_digest'],provider_scope_complete_original_digest=view.provider_scope_proof.original['original_digest']), 'scope_digest')
                    meter.write_row(db,'c09_provider_cleanup_scopes_v3',('selection_digest','scope_key','scope_json','scope_digest'),
                        (view.basis.selection_digest,scope_key,canonical(scope),scope['scope_digest']))
                else:
                    scope=json.loads(prior[0]);control.verify_original_v1(scope,'scope_digest')
                    if (scope['selection_digest'],scope['operation_id'],scope['provider_id'],scope['provider_config_digest'])!=(view.basis.selection_digest,self.operation_id,provider,cfg):
                        raise AuthorityUnavailable('actual provider configuration scope replay differs')
            self.model_count+=1;self.after=key[0]
            self.model_root=canonical_digest((self.model_root,self.model_count,model.call_id,model.original_digest,original['original_digest']))
        elif self.phase=='scopes':
            with control._db() as db:
                row=_bounded(db,meter).execute('SELECT scope_key,scope_json FROM c09_provider_cleanup_scopes_v3 WHERE selection_digest=? AND scope_key COLLATE BINARY>? ORDER BY scope_key COLLATE BINARY LIMIT 1',
                    (view.basis.selection_digest,self.after)).fetchone()
            if row is None:self.phase='completion'
            else:
                self.scope_key,self.scope=row[0],json.loads(row[1]);control.verify_original_v1(self.scope,'scope_digest')
                if (self.scope['selection_digest']!=view.basis.selection_digest or self.scope['operation_id']!=self.operation_id
                        or self.scope['provider_scope_complete_original_digest']!=view.provider_scope_proof.original['original_digest']):
                    raise AuthorityUnavailable('actual provider scope belongs to another selected complete inventory')
                self.purge=self.read=None;self.phase='purge'
        elif self.phase in ('purge','read'):
            action=self.phase
            if self.request is None:
                body=dict(schema='sylanne3.c09.provider-cache-request.v2',action=action,provider_id=service.provider_id,
                    installation_id=control.installation_id,authority_id=control.authority_id,namespace=view.basis.prepared['namespace'],
                    operation_id=self.operation_id,manifest_digest=view.basis.manifest['manifest_digest'],scope='installation_namespace_exact_provider_config_prompt_caches',
                    receipt_id=None if action=='purge' else self.purge['payload']['receipt_id'],
                    provider_config_scopes=((self.scope['provider_id'],self.scope['provider_config_digest']),),
                    scope_inventory_digest=view.provider_scope_proof.original['original_digest'])
                self.request={**body,'request_digest':digest(body)}
                with control._db(write=True) as db:
                    plan=_bounded(db,meter).execute('SELECT request_json FROM c09_provider_cleanup_requests_v3 WHERE selection_digest=? AND scope_key=? AND action=?',
                        (view.basis.selection_digest,self.scope_key,action)).fetchone()
                    if plan is None:
                        plan=control.sign_original_v1('sylanne3.c09.provider-cache-request-plan.v3',dict(schema='sylanne3.c09.provider-cache-request-plan.v3',
                            selection_digest=view.basis.selection_digest,operation_id=self.operation_id,scope_digest=self.scope['scope_digest'],
                            request=self.request,adapter_sha256=service.executable_sha256,public_key_sha256=service.public_key_sha256),'plan_digest')
                        meter.write_row(db,'c09_provider_cleanup_requests_v3',('selection_digest','scope_key','action','request_json','request_digest'),
                            (view.basis.selection_digest,self.scope_key,action,canonical(plan),plan['plan_digest']))
                    else:
                        plan=json.loads(plan[0]);control.verify_original_v1(plan,'plan_digest')
                        if (plan['selection_digest']!=view.basis.selection_digest or plan['operation_id']!=self.operation_id
                                or plan['scope_digest']!=self.scope['scope_digest'] or plan['request']!=json.loads(canonical(self.request))
                                or plan['adapter_sha256']!=service.executable_sha256 or plan['public_key_sha256']!=service.public_key_sha256):
                            raise AuthorityUnavailable('actual provider adapter request plan changed before an effect')
                with control._db() as db:
                    retained=_bounded(db,meter).execute('SELECT response_json FROM c09_provider_cleanup_responses_v3 WHERE selection_digest=? AND scope_key=? AND action=?',
                        (view.basis.selection_digest,self.scope_key,action)).fetchone()
                if retained is not None:
                    response=json.loads(retained[0]);control.verify_original_v1(response,'response_digest')
                    if (response['selection_digest']!=view.basis.selection_digest or response['operation_id']!=self.operation_id
                            or response['scope_digest']!=self.scope['scope_digest'] or response['request']!=json.loads(canonical(self.request))):
                        raise AuthorityUnavailable('actual provider response replay request changed')
                    envelope=_verify_provider_envelope_v3(service,self.request,response['provider_original'],meter)
                    if action=='purge':self.purge=envelope;self.request=None;self.phase='read';return dict(status='progress',phase='provider_purge_replay')
                    if self.saved_original is None:
                        self.read=envelope;self.request=None;self.phase='adopt';return dict(status='progress',phase='provider_read_replay')
                self.work=_InstalledProviderAdapterWorkV3(service,self.request)
                return dict(status='progress',phase='provider_adapter_pin')
            if not self.work.advance(meter):return dict(status='progress',phase='provider_adapter_'+self.work.phase)
            envelope=self.work.result;self.work=None
            response=control.sign_original_v1('sylanne3.c09.provider-cache-response.v3',dict(schema='sylanne3.c09.provider-cache-response.v3',
                selection_digest=view.basis.selection_digest,operation_id=self.operation_id,scope_digest=self.scope['scope_digest'],
                request=self.request,provider_original=envelope),'response_digest')
            with control._db(write=True) as db:
                prior=_bounded(db,meter).execute('SELECT response_json FROM c09_provider_cleanup_responses_v3 WHERE selection_digest=? AND scope_key=? AND action=?',
                    (view.basis.selection_digest,self.scope_key,action)).fetchone()
                if prior is None:meter.write_row(db,'c09_provider_cleanup_responses_v3',('selection_digest','scope_key','action','response_json','response_digest'),
                    (view.basis.selection_digest,self.scope_key,action,canonical(response),response['response_digest']))
                elif json.loads(prior[0])['provider_original']['payload']!=envelope['payload']:
                    raise AuthorityUnavailable('actual provider independent signed absence changed')
            self.request=None
            if action=='purge':self.purge=envelope;self.phase='read'
            else:self.read=envelope;self.phase='adopt'
        elif self.phase=='adopt':
            self.scope_count+=1;self.after=self.scope_key
            self.scope_root=canonical_digest((self.scope_root,self.scope_count,self.scope_key,self.purge['payload'],self.read['payload']))
            self.phase='scopes';self.scope=self.purge=self.read=None
        elif self.phase=='completion':
            observations=[dict(kind='actual_provider_scope_eof_v3',provider_id=service.provider_id,scope_count=self.scope_count,scope_root=self.scope_root,
                model_count=self.model_count,model_root=self.model_root,provider_scope_complete_original_digest=view.provider_scope_proof.original['original_digest'])]
            if self.saved_original is not None:
                control.verify_original_v1(self.saved_original,'evidence_digest')
                if (self.saved_original['operation_id']!=self.operation_id or self.saved_original['manifest_digest']!=view.basis.manifest['manifest_digest']
                        or self.saved_original['surface']!='model_prompt_caches' or self.saved_original['after_observations']!=observations):
                    raise AuthorityUnavailable('actual independent provider full EOF evidence differs')
                self.original=self.saved_original
            else:
                complete=record_selected_history_checkpoint_v3(view.basis,consumer='provider_cache',details=dict(schema='sylanne3.c09.provider-cache-complete.v3',
                    model_count=self.model_count,model_root=self.model_root,scope_count=self.scope_count,scope_root=self.scope_root,
                    provider_scope_complete_original_digest=view.provider_scope_proof.original['original_digest'],complete=True),meter=meter)
                self.original=control.sign_original_v1('sylanne3.c09.surface-evidence.v1',dict(schema='sylanne3.c09.surface-evidence.v1',
                    installation_id=control.installation_id,issuer_id=control.authority_id,operation_id=self.operation_id,surface='model_prompt_caches',
                    manifest_digest=view.basis.manifest['manifest_digest'],action='purged',plan_digest=complete['checkpoint_digest'],
                    before_observations=[dict(kind='actual_full_historical_provider_scopes_v3',original_digest=view.provider_scope_proof.original['original_digest'])],
                    after_observations=observations),'evidence_digest')
            return dict(status='complete',phase='provider_cache_complete',original=self.original)
        else:raise AuthorityUnavailable('actual provider cleanup phase differs')
        return dict(status='progress',phase='provider_cache_'+self.phase)
