"""Same installed Graph inode serialization for the natural disposition family.

The file descriptor is read-only. This never opens a new ledger or a side file,
and never grants Graph mutation permission. Every family writer rechecks its
actual Core permit after acquiring this barrier.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import stat
import sys


class NaturalGraphWriteBarrierHoldV1(RuntimeError):
    """Busy, unsupported or replaced actual Graph inode: keep the original HOLD."""


@dataclass(frozen=True, slots=True)
class NaturalGraphWriteBarrierV1:
    graph_path: Path
    device: int
    file_id: int
    fd: int

    def require_current_inode(self):
        current=os.stat(self.graph_path,follow_symlinks=False)
        opened=os.fstat(self.fd)
        if ((current.st_dev,current.st_ino)!=(self.device,self.file_id)
                or (opened.st_dev,opened.st_ino)!=(self.device,self.file_id)):
            raise NaturalGraphWriteBarrierHoldV1("natural family installed Graph inode changed")


@contextmanager
def natural_final_graph_barrier_v1(*, graph_path, expected_device, expected_file_id):
    if sys.platform!="linux":
        raise NaturalGraphWriteBarrierHoldV1("natural family inode recovery barrier requires Linux")
    import fcntl
    path=Path(graph_path)
    if not path.is_absolute():
        raise NaturalGraphWriteBarrierHoldV1("natural family barrier requires the installed absolute Graph path")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev,opened.st_ino)!=(expected_device,expected_file_id)):
            raise NaturalGraphWriteBarrierHoldV1("natural family barrier selected another Graph inode")
        barrier=NaturalGraphWriteBarrierV1(path,opened.st_dev,opened.st_ino,fd)
        barrier.require_current_inode()
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NaturalGraphWriteBarrierHoldV1("natural family original writer is still in flight") from exc
        try:
            barrier.require_current_inode()
            yield barrier
            barrier.require_current_inode()
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def natural_graph_barrier_for_store_v1(store, identity):
    """Compare the trusted connected Graph to an actual independent C09 read."""
    from ..authority_service.natural_disposition_maintenance_v1 import NaturalGraphIdentityV1
    if type(identity) is not NaturalGraphIdentityV1:
        raise NaturalGraphWriteBarrierHoldV1("natural writer needs the independent current C09 identity")
    with store._lock:
        if store._db.in_transaction:
            raise NaturalGraphWriteBarrierHoldV1("natural inode barrier must precede its Graph transaction")
        main=[row for row in store._db.execute("PRAGMA database_list") if row[1]=="main"]
        if len(main)!=1 or Path(main[0][2]).resolve(strict=True)!=Path(identity.graph_path):
            raise NaturalGraphWriteBarrierHoldV1("natural writer connected another installed Graph")
        row=store._db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",identity.namespace.as_tuple).fetchone()
        import json
        if row is None or json.loads(row[0])["graph_incarnation"]!=identity.graph_incarnation:
            raise NaturalGraphWriteBarrierHoldV1("natural writer connected an old Graph incarnation")
    with natural_final_graph_barrier_v1(graph_path=identity.graph_path,
            expected_device=identity.graph_device,expected_file_id=identity.graph_file_id) as barrier:
        yield barrier
