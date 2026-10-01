"""Real numeric Authority assembly for the existing installed after-drive case.

This never plants Owner/preparation/claim/measurement/adoption originals. It
adds the real numeric service and paired RPC client to a fixture that already
performed actual signed initialization, C02, paid appraisal and semantic drive.
The observed current four-file initial selection is not a C09 erasure/rebase or
privileged Linux installation claim.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass
import hmac
import os
from pathlib import Path
import sqlite3
import tempfile
import time

from sylanne3.authority_service.c09_storage_control_v1 import (
    C09StorageControlV1, InstalledC09InstanceLeaseV1, ROLES, digest, file_observation_v1,
)
from sylanne3.authority_service.c09_authority_storage_rebase import _objects, _root
from sylanne3.authority_service.d04_numeric_service_v3 import AuthorityD04NumericServiceV3
from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1
from sylanne3.host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
from sylanne3.runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
from sylanne3.runtime_contracts import canonical_digest


@dataclass
class ActualNumericAuthorityCaseV3:
    authority: AuthorityD04NumericServiceV3
    port: InstalledC04AuthorityPortV3
    storage_control: C09StorageControlV1
    lease: InstalledC09InstanceLeaseV1
    protected_directory: object
    root_authority: object = None

    def close(self):
        """Call only after the outer installed fixture has closed its stores."""
        self.lease.close()
        self.protected_directory.cleanup()


def install_actual_numeric_authority_case_v3(case, *, owner_loop):
    graph,store,core=case["graph"],case["store"],case["core"]
    namespace=case["authority_namespace"]
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    bundle=case["installed_bundle"] if assembly is None else assembly.admin_bundle
    bridge=case["server"]._v2_execution[namespace]
    if bridge.core is not core or "execution" in case and bridge.journal is not case["execution"]:
        raise AssertionError("numeric fixture must use actual existing independent journals")
    existing=getattr(graph,"_actual_d04_authority_acceptance_v3",None)
    if existing is not None:
        if (type(existing) is not ActualNumericAuthorityCaseV3 or existing.authority.bridge is not bridge
                or getattr(core,"_c09_storage_reader_v1",None) is not existing.storage_control):
            raise AssertionError("root/numeric actual current assembly changed")
        existing.port=InstalledC04AuthorityPortV3(client=case["authority_client"],bundle=bundle,
            grant=case["client_grant"],owner_loop=owner_loop)
        graph._GraphCoordinator__c04_authority_port_v3=existing.port
        return existing
    initial=getattr(graph,"_initial_offline_storage_case_v1",None)
    if initial is None and getattr(core,"_c09_storage_reader_v1",None) is not None:
        raise AssertionError("numeric fixture must not replace an existing current storage selection")
    protected=(tempfile.TemporaryDirectory(prefix="sylanne-numeric-current-control-")
        if initial is None else initial.protected_directory)
    protected_root=Path(protected.name)
    lease=(InstalledC09InstanceLeaseV1(protected_root/"instance.lock") if initial is None else initial.lease)
    try:
        if initial is not None:
            control=initial.storage_control
            assert getattr(core,"_c09_storage_reader_v1",None) is control
            files={"core":Path(core.path).resolve(),"deletion":Path(bridge.deletion.path).resolve(),
                "execution":Path(bridge.journal.path).resolve(),
                "graph":Path(store._db.execute("PRAGMA database_list").fetchone()[2]).resolve()}
            control.read_verified_current_storage_v1().require_current("business")
        else:
            key=protected_root/"control.key";key.write_bytes(os.urandom(32))
            files={"core":Path(core.path).resolve(),"deletion":Path(bridge.deletion.path).resolve(),
                "execution":Path(bridge.journal.path).resolve(),
                "graph":Path(store._db.execute("PRAGMA database_list").fetchone()[2]).resolve()}
            roots=tuple(sorted({path.parent for path in files.values()}))
            control=C09StorageControlV1(control_path=protected_root/"control.db",key_path=key,
                installation_id=bundle.installation_policy.installation_id,authority_id=case["client_grant"].authority_id,
                control_store_id="numeric-acceptance-control",key_id="numeric-acceptance-key",lease=lease,resource_roots=roots)
            managed_root=files["graph"].parent/"numeric-managed-artifacts";managed_root.mkdir()
            directories={name:managed_root/name for name in ("controlled_backup","export","rebuild_temp","cache")}
            for path in directories.values():path.mkdir()
            inventory=build_initial_inventory_v1(authority_id=control.authority_id,installation_id=control.installation_id,
                namespace=namespace,files=files,directories=directories)
            # Hold the actual existing writers in their canonical order; this is
            # initial selection of the same stores, not data replacement. Each WAL
            # checkpoint and independently opened read below observes real bytes.
            with bridge.deletion._lock,bridge.journal._lock,core._lock,store._lock:
                if core._db.in_transaction or store._db.in_transaction:
                    raise AssertionError("numeric assembly requires settled actual stores")
                with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
                    deletion_head=bridge.deletion.verified_head()
                    execution_head=bridge.journal.verified_head()
                # The SQL writer transactions above are closed. The real process
                # writer RLocks remain held while independent connections checkpoint.
                for path in files.values():
                    with closing(sqlite3.connect(path)) as db:
                        if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]!=0:
                            raise AssertionError("actual initial storage checkpoint is busy")
                metadata,_=graph._v2_graph_stamp(case["namespace"])
                identities={"core":control.authority_id,"deletion":deletion_head.journal_id,
                    "execution":execution_head.journal_id,"graph":metadata.requirements.graph_incarnation}
                members=[]
                for role in ROLES:
                    observation=file_observation_v1(files[role],exclusive=True)
                    with closing(sqlite3.connect(files[role].as_uri()+"?mode=ro",uri=True)) as db:
                        db.execute("PRAGMA query_only=ON")
                        if db.execute("PRAGMA quick_check").fetchone()!=("ok",):raise AssertionError("actual current SQLite integrity failed")
                        schema,logical=digest(_objects(db)),_root(db)
                    members.append(dict(role=role,**observation,store_id=control.authority_id+":"+role,
                        schema_version=("2" if role=="deletion" else str(bridge.journal._schema_version) if role=="execution" else "1"),namespace=namespace,storage_generation=0,incarnation_or_journal_id=identities[role],
                        logical_data_root=logical,schema_objects_digest=schema,
                        cold_read_digest=digest(("independent_read_only_connection",role,schema,logical,observation)),
                        wal_policy="checkpointed_guarded_initial_selection",companion_resource_ids=[role+":wal",role+":shm",role+":journal"]))
                manifest=dict(schema="sylanne3.c09.storage_manifest.v1",authority_id=control.authority_id,
                    installation_id=control.installation_id,cohort_namespaces=[namespace],generation=0,
                    prior_manifest_digest=None,members=members,inventory_manifest_digest=inventory.manifest_digest,
                    certificate_digest=None,graph_issue_digest=None,recovery_pin_digest=None,
                    cumulative_tombstone_root=canonical_digest(()),deletion_watermark=metadata.requirements.deletion_seq)
                manifest["manifest_digest"]=digest(manifest)
                control.bootstrap_installed_storage_v1(manifest=manifest)
            core.install_current_c09_storage_reader_v1(reader=control)
        service=AuthorityD04NumericServiceV3(bridge=bridge,owner_tickets=case["server"]._v2_owner_tickets,
            namespace=case["namespace"],installation_id=control.installation_id,graph_db_path=files["graph"],
            resource_issuer=case["d02_issuer"],budget_issuer=case["d11_issuer"],credential=case["peer"],
            signing_key=hmac.digest(bundle.d11_signing_key,b"sylanne3.numeric-acceptance.v3\0"+control.installation_id.encode(),"sha256"),
            trusted_now_utc=time.time,installed_identity=read_installed_d04_numeric_identity_v3(case["package_root"],case["manifest_digest"]))
        # The actual RPC adapter intentionally hides service exceptions. Keep
        # permanent acceptance diagnostics without changing or replacing a gate.
        import functools,traceback
        def diagnosed(method):
            @functools.wraps(method)
            def call(*args,**kwargs):
                try:return method(*args,**kwargs)
                except Exception:
                    traceback.print_exc()
                    raise
            return call
        for name in ("claim_d04_numeric_v3","begin_d04_numeric_original_append_v3","record_d04_numeric_terminal_v3",
                "begin_d04_numeric_adoption_bridge_v3","validate_d04_numeric_gate_v3",
                "finish_d04_numeric_adoption_bridge_v3","read_d04_numeric_restore_original_v3",
                "read_d04_numeric_restore_packet_bytes_v3"):
            setattr(service,name,diagnosed(getattr(service,name)))
        case["server"].install_d04_numeric_service_v3(namespace,service)
        from sylanne3.authority_service.d04_series_service_v1 import AuthorityD04SeriesServiceV1
        series = AuthorityD04SeriesServiceV1(numeric_service=service)
        for name in ("claim", "inspect", "terminal", "gate", "validate_gate", "finish", "restore_bytes"):
            setattr(series, name, diagnosed(getattr(series, name)))
        case["server"]._d04_series_services_v1[namespace] = series
        core.install_execution_redaction_d04_series_service_v1(namespace, series)
        from sylanne3.authority_service.installed_c04_executor_v3 import compose_installed_c04_executor_v3
        c04_service,c04_executor=compose_installed_c04_executor_v3(
            bridge=bridge,namespace=case["namespace"],graph_db_path=files["graph"],
            package_root=case["package_root"],trusted_manifest_sha256=case["manifest_digest"],
            component_signing_key=hmac.digest(bundle.d11_signing_key,
                b"sylanne3.c04-acceptance.v3\0"+control.installation_id.encode(),"sha256"),
            credential=case["peer"],resource_issuer=case["d02_issuer"],budget_issuer=case["d11_issuer"])
        core.install_execution_redaction_c04_services(namespace,{"d06.association_activation.v3":c04_service})
        case["server"].install_c04_executor_v3(namespace,c04_service,c04_executor)
        from sylanne3.authority_service.d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
        from sylanne3.host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
        root_service=AuthorityD04RootExecutionServiceV3(bridge=bridge,owner_tickets=case["server"]._v2_owner_tickets,
            namespace=case["namespace"],installation_id=control.installation_id,graph_db_path=files["graph"],
            resource_issuer=case["d02_issuer"],budget_issuer=case["d11_issuer"],credential=case["peer"],
            signing_key=hmac.digest(bundle.d11_signing_key,b"sylanne3.root-acceptance.v3\0"+control.installation_id.encode(),"sha256"),
            trusted_now_utc=time.time,installed_identity=read_installed_d04_root_identity_v3(case["package_root"],case["manifest_digest"]))
        for name in ("claim_d04_root_v3","begin_d04_root_original_append_v3","record_d04_root_terminal_v3",
                "begin_d04_root_adoption_bridge_v3","validate_d04_root_gate_v3","finish_d04_root_adoption_bridge_v3",
                "read_d04_root_restore_original_v3"):
            setattr(root_service,name,diagnosed(getattr(root_service,name)))
        if not hasattr(case["server"],"_d04_root_services_v3"):case["server"]._d04_root_services_v3={}
        case["server"]._d04_root_services_v3[namespace]=root_service
        core.install_execution_redaction_d04_root_service_v3(namespace,root_service)
        port=InstalledC04AuthorityPortV3(client=case["authority_client"],bundle=bundle,
            grant=case["client_grant"],owner_loop=owner_loop)
        graph._GraphCoordinator__c04_authority_port_v3=port
        result=ActualNumericAuthorityCaseV3(service,port,control,lease,protected,root_service)
        graph._actual_d04_authority_acceptance_v3=result
        return result
    except BaseException:
        lease.close();protected.cleanup();raise


def install_actual_root_authority_case_v3(case,*,owner_loop):
    """Install real current storage/Authority before the first root preparation.

    The same exact service is reused by later after-drive numeric acceptance.
    Caller owns close after the outer real Owner fixture has finished logout.
    """
    return install_actual_numeric_authority_case_v3(case,owner_loop=owner_loop)
