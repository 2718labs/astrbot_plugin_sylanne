"""True two-process inode/finished-fence boundaries, not installed C09/P2 acceptance.

The actual durable V2 fence store is exercised through its public APIs. The
provided anchor is this storage fixture's anchor; this does not attest journals,
Owner authentication, paid originals, or an installed Core signing composition.
"""
from contextlib import closing
import multiprocessing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import from_wire, to_wire
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime.natural_disposition_write_barrier_v1 import (
    NaturalGraphWriteBarrierHoldV1, natural_final_graph_barrier_v1,
)


def _anchor():
    return RestoreAnchor(authority_id="inode-boundary-authority",namespace="inode-boundary",
        activation_generation=1,deletion_journal_id="inode-delete",deletion_seq=0,deletion_digest="genesis",
        execution_journal_id="inode-execution",execution_seq=0,execution_digest="genesis",
        revocation_epoch=0,proof="storage-boundary-only")


def _open_fences(path, create=False):
    db=sqlite3.connect(path,isolation_level=None)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA synchronous=FULL")
    return db,AuthorityV2FenceStore(db,create=create)


def _writer_process(graph_path,core_path,permit_wire,channel,mode):
    try:
        identity=Path(graph_path).stat()
        permit=from_wire(permit_wire)
        if mode=="in_flight":
            with natural_final_graph_barrier_v1(graph_path=graph_path,expected_device=identity.st_dev,expected_file_id=identity.st_ino):
                with closing(sqlite3.connect(graph_path,isolation_level=None)) as graph:
                    graph.execute("BEGIN IMMEDIATE")
                    channel.send({"state":"holding_original_writer"})
                    assert channel.recv()=="commit_once"
                    graph.execute("INSERT INTO fixture_writes(value) VALUES('actual-first-writer')")
                    graph.execute("COMMIT")
            channel.send({"state":"committed_once"})
        else:
            channel.send({"state":"ready_before_inode_lock"})
            assert channel.recv()=="try_busy_once"
            try:
                with natural_final_graph_barrier_v1(graph_path=graph_path,expected_device=identity.st_dev,expected_file_id=identity.st_ino):
                    raise AssertionError("second process entered an actual held inode barrier")
            except NaturalGraphWriteBarrierHoldV1:
                channel.send({"state":"busy_hold"})
            assert channel.recv()=="try_late_once"
            with natural_final_graph_barrier_v1(graph_path=graph_path,expected_device=identity.st_dev,expected_file_id=identity.st_ino):
                db,store=_open_fences(core_path)
                with closing(db):
                    try:
                        store.validate_fence(permit,subject="inode-subject",current_anchor=_anchor())
                    except AuthorityUnavailable:
                        channel.send({"state":"finished_permit_rejected_before_graph_write"})
                    else:
                        raise AssertionError("late writer reused its finished actual Core permit")
    except BaseException as exc:
        channel.send({"state":"child_failure","type":type(exc).__name__,"detail":str(exc)})
        raise
    finally:
        channel.close()


@unittest.skipUnless(sys.platform=="linux","actual RO inode flock protocol requires Linux")
class NaturalDispositionInodeProcessTests(unittest.TestCase):
    def _fixture(self, directory):
        graph=Path(directory)/"graph.sqlite3";core=Path(directory)/"core.sqlite3"
        with sqlite3.connect(graph) as db:db.execute("CREATE TABLE fixture_writes(value TEXT NOT NULL)")
        db,store=_open_fences(core,True)
        with closing(db):
            permit=store.begin_fence(subject="inode-subject",holder="inode-holder",operation="write",
                operation_id="natural-disposition:actual-inode-boundary",current_anchor=_anchor())
        return graph,core,permit

    def _receive(self, connection):
        self.assertTrue(connection.poll(10),"bounded IPC child did not return its actual state")
        result=connection.recv()
        self.assertNotEqual(result["state"],"child_failure",result)
        return result["state"]

    def test_in_flight_writer_makes_independent_recovery_busy_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            graph,core,permit=self._fixture(directory);identity=graph.stat()
            parent,child=multiprocessing.get_context("spawn").Pipe()
            worker=multiprocessing.get_context("spawn").Process(target=_writer_process,
                args=(str(graph),str(core),to_wire(permit),child,"in_flight"))
            worker.start();child.close()
            try:
                self.assertEqual(self._receive(parent),"holding_original_writer")
                with self.assertRaises(NaturalGraphWriteBarrierHoldV1):
                    with natural_final_graph_barrier_v1(graph_path=graph,expected_device=identity.st_dev,expected_file_id=identity.st_ino):
                        self.fail("recovery must not inspect absence/finish while the old writer is in flight")
                db,store=_open_fences(core)
                with closing(db):self.assertEqual(store.get_operation(permit.operation_id,subject="inode-subject",namespace=_anchor().namespace)[1],"active")
                parent.send("commit_once")
                self.assertEqual(self._receive(parent),"committed_once")
                with sqlite3.connect(graph) as db:self.assertEqual(db.execute("SELECT count(*) FROM fixture_writes").fetchone(),(1,))
            finally:
                parent.close();worker.join(10)
                if worker.is_alive():worker.terminate();worker.join(5)
            self.assertEqual(worker.exitcode,0)

    def test_late_writer_revalidates_finished_actual_permit_before_sql(self):
        with tempfile.TemporaryDirectory() as directory:
            graph,core,permit=self._fixture(directory);identity=graph.stat()
            parent,child=multiprocessing.get_context("spawn").Pipe()
            worker=multiprocessing.get_context("spawn").Process(target=_writer_process,
                args=(str(graph),str(core),to_wire(permit),child,"late"))
            worker.start();child.close()
            try:
                self.assertEqual(self._receive(parent),"ready_before_inode_lock")
                with natural_final_graph_barrier_v1(graph_path=graph,expected_device=identity.st_dev,expected_file_id=identity.st_ino):
                    parent.send("try_busy_once")
                    self.assertEqual(self._receive(parent),"busy_hold")
                    with sqlite3.connect(graph) as db:self.assertEqual(db.execute("SELECT count(*) FROM fixture_writes").fetchone(),(0,))
                    db,store=_open_fences(core)
                    with closing(db):store.finish_fence(permit,subject="inode-subject",current_anchor=_anchor(),
                        request_id="reject:"+permit.operation_id,request_digest="sha256:"+"f"*64)
                parent.send("try_late_once")
                self.assertEqual(self._receive(parent),"finished_permit_rejected_before_graph_write")
                with sqlite3.connect(graph) as db:self.assertEqual(db.execute("SELECT count(*) FROM fixture_writes").fetchone(),(0,))
            finally:
                parent.close();worker.join(10)
                if worker.is_alive():worker.terminate();worker.join(5)
            self.assertEqual(worker.exitcode,0)


if __name__=="__main__":unittest.main()
