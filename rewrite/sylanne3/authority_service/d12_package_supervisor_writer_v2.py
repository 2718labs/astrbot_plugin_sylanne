"""Private root one-shot journal writer with an exclusive installation lock.

Construction checks the actual fixed bootstrap code and protected original
files. No RPC accepts its methods or a caller-provided acceptance verdict.
"""
from contextlib import ExitStack
from dataclasses import asdict
import fcntl
import os
from pathlib import Path
import sqlite3
from .contract import AuthorityUnavailable
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
from .d12_package_supervisor_journal_v2 import _SupervisorJournalKernelV2,InstalledPackageSupervisorJournalV2
from .d12_package_maintenance_contract_v2 import D12PackageStageReceiptV2
from .d12_package_observation_v2 import build_supervisor_observation_v2
from .linux_installation_security_v1 import require_linux_administrator_v1,opened_installed_file_v1,read_installed_bytes_v1
from ..runtime_contracts import canonical_digest


class _InstalledPackageSupervisorWriterV2:
    def __init__(self):
        require_linux_administrator_v1()
        self.files=InstalledPackageSelectionFilesV2(control_directory='/etc/sylanne/maintenance')
        self.policy,self.host_config,self.authority_config=read_fixed_supervisor_policy_v2(self.files)
        if not Path(__file__).absolute().is_relative_to(Path(self.policy['bootstrap_root'])/'runtime'):
            raise AuthorityUnavailable('external maintenance must run from the actual fixed bootstrap runtime')
        self.directory=self.files.control_directory
        self.reader=InstalledPackageSupervisorJournalV2(control_directory=self.directory,
            supervisor_policy_digest=self.files.read_maintenance_policy_v2()['supervisor_policy_digest'])
        self._stack=ExitStack();self.db=None
        try:
            lock=self._stack.enter_context(opened_installed_file_v1(self.directory/'executor.lock',private=True,allowed_gid=0))
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fd=self._stack.enter_context(opened_installed_file_v1(self.directory/'supervisor.sqlite3',private=True,allowed_gid=0))
            before=os.fstat(fd);path=self.directory/'supervisor.sqlite3'
            self.db=sqlite3.connect(path,timeout=5)
            after=path.stat(follow_symlinks=False)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise AuthorityUnavailable('supervisor journal inode changed')
            private=read_installed_bytes_v1(self.directory/'journal-signing.key',limit=32,private=True,allowed_gid=0)
            self.kernel=_SupervisorJournalKernelV2(self.db,private,self.reader.policy)
            from cryptography.hazmat.primitives import serialization
            public=self.kernel.verifier.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            if public!=self.reader.public_key:raise AuthorityUnavailable('actual independent supervisor signing key differs')
        except BaseException:
            self.close();raise

    def close(self):
        if self.db is not None:self.db.close();self.db=None
        self._stack.close()

    def observe(self,operation_id,kind,body):
        original=build_supervisor_observation_v2(operation_id=operation_id,kind=kind,body=body)
        return self.kernel._record_observation(original)

    def prepare(self,operation_id,stage):
        return self.kernel._prepare_stage(operation_id,stage)

    def finish(self,operation_id,stage,observations):
        pending=self.reader.read_verified_pending_stage_v2(operation_id)
        intent=self.kernel.read_intent(operation_id)
        if pending is None or stage not in {pending['stage'],'failed'} or intent is None:
            raise AuthorityUnavailable('stage completion has no exact pending original')
        refs=tuple(sorted(set((o.observation_ref,o.observation_digest) for o in observations)))
        if not refs:refs=((intent.accepted_original_ref,intent.accepted_original_digest),)
        body=dict(schema='d12.compatible-package-stage.v2',operation_id=operation_id,
            accepted_original_digest=intent.digest,stage=stage,stage_sequence=pending['stage_sequence'],
            prior_receipt_digest=pending['prior_receipt_digest'],observation_refs=refs)
        receipt=D12PackageStageReceiptV2(**body,receipt_digest=canonical_digest(body))
        result=self.kernel._record_observed_stage(receipt)
        fd=os.open(self.directory/'supervisor.sqlite3',os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        return result
