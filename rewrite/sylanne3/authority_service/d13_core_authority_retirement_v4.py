"""Actual Root custody for a signed local Authority Core incarnation."""
from __future__ import annotations
from dataclasses import asdict
from weakref import WeakKeyDictionary
import os,select,socket,struct
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest

_ISSUER=object()
_CAPS=WeakKeyDictionary()


def _require_birth_v4(control,birth):
    from .d13_cache_use_contract_v2 import D13AuthorityCoreBirthReceiptV4,cache_use_from_wire_v2
    if type(birth)is not D13AuthorityCoreBirthReceiptV4 or cache_use_from_wire_v2(asdict(birth),D13AuthorityCoreBirthReceiptV4)!=birth:
        raise AuthorityUnavailable('actual closed typed Core birth original required')
    control.verify_original_v1(asdict(birth),'birth_digest')
    if (birth.authority_id,birth.installation_id,birth.control_store_id)!=(control.authority_id,control.installation_id,control.control_store_id):
        raise AuthorityUnavailable('Core retirement birth belongs to another actual Control')
    return birth


def core_authority_retirement_common_v4(birth,nonce):
    return dict(birth_profile=birth.birth_profile,birth_original_ref=birth.operation_id,
        birth_original_digest=birth.birth_digest,birth_selector_digest=canonical_digest(asdict(birth)),core_incarnation_id=birth.core_incarnation_id,
        authority_id=birth.authority_id,installation_id=birth.installation_id,control_store_id=birth.control_store_id,
        namespace=birth.authority_namespace,old_authority_process_original=birth.authority_process_original,
        birth_storage_manifest_digest=birth.selected_manifest_digest,birth_pointer_version=birth.pointer_version,
        birth_storage_generation=birth.storage_generation,old_root_observation_digest=birth.root_process_census_digest,
        observer_hold_nonce=nonce,complete=True)


def _require_current_and_lineage_v4(control,gate,birth,qualification):
    from ..runtime.d13_consumer_manifest_v3 import CurrentCoreBirthQualificationV4
    from .c09_selected_history_v3 import _bounded,VerifiedSelectedHistoryReadV3
    if type(qualification)is not CurrentCoreBirthQualificationV4:
        raise AuthorityUnavailable('actual independent current Core retirement qualification required')
    q=qualification.require_v4()
    if q.control is not control or q.gate is not gate or q.birth is None or q.daemon is None:
        raise AuthorityUnavailable('Core retirement crossed its actual current Root hold/new Core birth')
    _require_birth_v4(control,birth)
    if (birth.namespace!=q.birth.namespace or birth.consumer_cohort_digest!=q.birth.consumer_cohort_digest
            or birth.birth_profile!=q.consumer_mode or birth.core_incarnation_id==q.birth.core_incarnation_id):
        raise AuthorityUnavailable('old Core birth is not in the same explicit installed receiver cohort')
    with control._resource_sql_quantum_v3()as meter:
        if gate.require_pending_start_bootstrap_scope_v3(meter=meter)is not q.hold:
            raise AuthorityUnavailable('Core retirement lost its actual current Root hold')
        q.context.require_current('maintenance')
        with control._db()as raw:
            db=_bounded(raw,meter)
            manifest=control._read_manifest(db,birth.selected_manifest_digest)
            if manifest['generation']!=birth.storage_generation or birth.authority_namespace not in manifest['cohort_namespaces']:
                raise AuthorityUnavailable('old Core birth has no actual signed historical storage manifest')
            current=q.context
            if birth.storage_generation>current.storage_generation or birth.pointer_version>current.pointer_version:
                raise AuthorityUnavailable('old Core birth points beyond the actual selected history')
            if birth.storage_generation==current.storage_generation:
                if (birth.selected_manifest_digest,birth.pointer_version)!=(current.manifest_digest,current.pointer_version):
                    raise AuthorityUnavailable('old Core birth differs from its exact current signed storage point')
            else:
                view=q.daemon._resolved_storage_composition_v3.selected
                if type(view)is not VerifiedSelectedHistoryReadV3:
                    raise AuthorityUnavailable('old Core storage lineage requires its real complete selected history')
                view.require_current(meter=meter)
                if view.history_count<birth.storage_generation:
                    raise AuthorityUnavailable('old Core birth is outside the actual whole-history EOF')
                if birth.storage_generation==0:
                    row=db.execute('SELECT manifest_digest FROM c09_storage_manifests_v1 WHERE installation_id=? AND generation=0',
                        (control.installation_id,)).fetchone()
                    if row!=(birth.selected_manifest_digest,)or birth.pointer_version!=0:
                        raise AuthorityUnavailable('old Core birth is not the actual installed genesis in selected lineage')
                else:
                    row=db.execute('SELECT namespace,generation,expected_pointer_version FROM c09_storage_operations_v3 '
                        'WHERE installation_id=? AND new_manifest_digest=?',(control.installation_id,birth.selected_manifest_digest)).fetchone()
                    if row!=(birth.authority_namespace,birth.storage_generation,birth.pointer_version-1):
                        raise AuthorityUnavailable('old Core birth is absent from the actual authenticated prepared lineage')
    return q


class VerifiedInstalledCoreAuthorityRetirementV4:
    def __init__(self,issuer,*,control,gate,birth,qualification,original,custody):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual Root Core-retirement issuer required')
        self.control,self.gate,self.birth,self.qualification=control,gate,birth,qualification
        self.original,self.custody=original,custody;self.closed=False
        _CAPS[self]=(control,gate,birth,qualification,canonical_digest(original),custody)
    def require_current(self,*,control,gate,birth,qualification):
        from .d13_cache_use_contract_v2 import validate_core_authority_retirement_original_v4
        if (type(self)is not VerifiedInstalledCoreAuthorityRetirementV4 or self.closed
                or _CAPS.get(self)!=(control,gate,birth,qualification,canonical_digest(self.original),self.custody)):
            raise AuthorityUnavailable('actual Core-retirement private custody binding changed')
        q=_require_current_and_lineage_v4(control,gate,birth,qualification)
        validate_core_authority_retirement_original_v4(self.original,birth_profile=birth.birth_profile)
        common=core_authority_retirement_common_v4(birth,self.original['observer_hold_nonce'])
        if any(self.original[name]!=value for name,value in common.items()):
            raise AuthorityUnavailable('actual Root retirement differs from its exact signed old Core birth')
        if birth.birth_profile=='production_root':
            channel,pidfd,boot=self.custody
            from .installed_root_lifetime_observer_v3 import _boot
            if (channel.fileno()<0 or select.select([channel],[],[],0)[0]or select.select([pidfd],[],[],0)[0]
                    or _boot()!=boot):
                raise AuthorityUnavailable('actual outer Root Core retirement custody ended')
        elif birth.birth_profile=='controlled_sdk':
            if self.custody is not q.hold:raise AuthorityUnavailable('actual SDK retirement crossed its current held Root channel')
            self.custody.require_current()
            if self.original['current_root_census_digest']!=self.custody.digest:
                raise AuthorityUnavailable('SDK retirement changed its actual current Root census')
        else:raise AuthorityUnavailable('unknown actual Core retirement profile')
        return self.original
    def release_v4(self):
        if self.closed:return
        if self.birth.birth_profile=='production_root':
            from .installed_root_lifetime_observer_v3 import _send,_packet
            channel,pidfd,_=self.custody
            try:
                _send(channel,dict(action='release_core_authority_custody_v4',observer_hold_nonce=self.original['observer_hold_nonce']))
                if _packet(channel)!=dict(status='core_authority_custody_released_v4',observer_hold_nonce=self.original['observer_hold_nonce']):
                    raise AuthorityUnavailable('actual Root Core retirement release acknowledgement differs')
            finally:channel.close();os.close(pidfd);self.closed=True;_CAPS.pop(self,None)
        else:self.closed=True;_CAPS.pop(self,None)


def read_installed_core_authority_retirement_v4(*,control,gate,birth,producer_original):
    """Read OS custody outside Core/Graph SQL; a progress reply alone returns None."""
    q=_require_current_and_lineage_v4(control,gate,birth,producer_original)
    if q.core._db.in_transaction or q.daemon.c09_maintenance.graph._db.in_transaction:
        raise AuthorityUnavailable('Root physical retirement read cannot run inside Core/Graph SQL')
    if birth.birth_profile=='controlled_sdk':
        original=q.hold.read_core_authority_retirement_v4(birth=birth)
        if original is None:return None
        cap=VerifiedInstalledCoreAuthorityRetirementV4(_ISSUER,control=control,gate=gate,birth=birth,
            qualification=q,original=original,custody=q.hold)
    elif birth.birth_profile=='production_root':
        from .installed_root_lifetime_observer_v3 import read_installed_root_lifetime_spec_v3,_send,_retirement_packet,_boot
        spec=read_installed_root_lifetime_spec_v3()
        if (spec['authority_id'],spec['installation_id'])!=(control.authority_id,control.installation_id):
            raise AuthorityUnavailable('actual outer Root installation differs from current Control')
        channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        channel.settimeout(q.hold.channel.gettimeout())
        pidfd=None
        try:
            channel.connect(spec['control_socket_path'])
            pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=0 or pid!=0:raise AuthorityUnavailable('actual outer Root ancestor credential required')
            _send(channel,dict(action='retire_core_authority_v4',spec_digest=spec['spec_digest'],birth_original=asdict(birth)))
            reply,pidfd=_retirement_packet(channel)
            if reply==dict(status='progress',phase='core_authority_retirement_v4'):
                channel.close();os.close(pidfd);return None
            if type(reply)is not dict or set(reply)!={'status','original'}or reply['status']!='core_authority_retired_v4':
                raise AuthorityUnavailable('actual outer Root Core-retirement reply is unknown')
            original=reply['original'];old=birth.root_observation_original
            if (original['old_root_process_original']!=old['launcher_process_original']
                    or original['old_pid_namespace_identity']!=old['pid_namespace_identity']
                    or original['old_mount_namespace_identity']!=old['mount_namespace_identity']
                    or original['observer_spec_digest']!=spec['spec_digest']or original['kernel_boot_id']!=_boot()):
                raise AuthorityUnavailable('actual outer Root retirement crossed the signed old Authority Root namespace')
            cap=VerifiedInstalledCoreAuthorityRetirementV4(_ISSUER,control=control,gate=gate,birth=birth,
                qualification=q,original=original,custody=(channel,pidfd,original['kernel_boot_id']))
        except BaseException:
            channel.close()
            if pidfd is not None:os.close(pidfd)
            raise
    else:raise AuthorityUnavailable('unknown actual Core retirement profile')
    try:cap.require_current(control=control,gate=gate,birth=birth,qualification=q)
    except BaseException:
        cap.release_v4();raise
    return cap
