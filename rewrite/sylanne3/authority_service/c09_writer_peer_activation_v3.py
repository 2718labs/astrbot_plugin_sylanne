"""Installed complete Root process census used only for peer registry activation."""
from __future__ import annotations
from dataclasses import asdict
from weakref import WeakSet
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest

_CENSUSES_V3=WeakSet()


class InstalledPeerRegistryCensusV3:
    def __init__(self,*,supervisor,inventory_manifest,peer):
        from .installed_process_supervisor_v1 import InstalledRootProcessSupervisorV1
        from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
        if (type(supervisor) is not InstalledRootProcessSupervisorV1
                or type(inventory_manifest) is not InstallationFilesystemManifestV2
                or supervisor.config.service_role!='host'
                or supervisor.config.installation_id!=inventory_manifest.installation_id
                or supervisor.config.authority_id!=inventory_manifest.authority_id
                or supervisor.config.namespace_cohort!=(inventory_manifest.namespace,)
                or peer[1]!=supervisor.config.profile_id):
            raise AuthorityUnavailable('actual installed finite Root Host cohort census required')
        self.supervisor,self.inventory,self.peer=supervisor,inventory_manifest,peer
        self.control=self.config=self.context=None
        self.hold=self._continuation=None
        self.complete=False
        _CENSUSES_V3.add(self)

    def begin(self,*,control,config,context):
        if self not in _CENSUSES_V3 or self.control is not None:
            raise AuthorityUnavailable('installed Root census begins once per selected bootstrap')
        if (tuple(key for key,value in config.installations_v2.items()
                if value.installation_id==control.installation_id)!=(self.peer,)
                or config.installations_v2[self.peer].installation_id!=control.installation_id
                or self.inventory.installation_id!=control.installation_id
                or self.inventory.authority_id!=control.authority_id
                or context.stage!='READY' or context.pointer_version!=0 or context.storage_generation!=0
                or context.manifest['inventory_manifest_digest']!=self.inventory.manifest_digest):
            raise AuthorityUnavailable('missing registry requires actual initial prehost installation genesis; migration HOLD')
        self.control,self.config,self.context=control,config,context
        self.scope=dict(authority_id=control.authority_id,installation_id=control.installation_id,
            namespace=self.inventory.namespace,manifest_digest=context.manifest_digest,
            pointer_version=0,storage_generation=0,
            peer_cohort_digest=canonical_digest(dict(peer=self.peer,supervisor_spec_digest=self.supervisor.config.spec_digest,
                inventory_manifest_digest=self.inventory.manifest_digest)))

    def advance(self):
        if self not in _CENSUSES_V3 or self.control is None:
            raise AuthorityUnavailable('actual installed census selected scope required')
        if not self.complete:
            self._continuation=self.supervisor.hold_peer_registry_genesis_v3(registry_scope=self.scope)
            self.hold=self._continuation.__enter__()
            self.hold.require_current()
            self.complete=True
        return dict(status='complete',phase='writer_peer_process_census')

    def require_current(self,*,control,gate,meter):
        if (self not in _CENSUSES_V3 or not self.complete or self.control is not control
                or self.config is not gate._installed_config_v3 or gate.control is not control):
            raise AuthorityUnavailable('actual installed complete process census changed its Gate scope')
        self.hold.require_current()
        control.lease.require_held()
        self.context.require_current('maintenance')
        return self

    def activation_summary_v3(self,*,control,gate,meter):
        self.require_current(control=control,gate=gate,meter=meter)
        observation=asdict(self.hold.observation)
        process_root=canonical_digest(dict(schema='sylanne3.c09.root-peer-process-census.v3',
            scope=self.scope,observation=observation))
        return dict(schema='sylanne3.c09.writer-peer-registry-activation-input.v3',mode='genesis',
            installation_inventory_digest=self.inventory.manifest_digest,process_count=0,
            process_root=process_root,process_eof_digest=canonical_digest(dict(schema='sylanne3.c09.root-peer-process-census-eof.v3',
                scope=self.scope,process_root=process_root,observation_digest=self.hold.observation.observation_digest,
                root_channel_nonce=self.hold.original['root_channel_nonce'])),
            legacy_quiescence_count=0,legacy_quiescence_root=canonical_digest(()),legacy_quiescence_eof_digest=canonical_digest(()),
            root_channel_nonce=self.hold.original['root_channel_nonce'],supervisor_spec_digest=self.supervisor.config.spec_digest,
            root_process_original=self.hold.launcher_original)

    def close(self):
        if self._continuation is not None:
            continuation,self._continuation=self._continuation,None
            continuation.__exit__(None,None,None)
