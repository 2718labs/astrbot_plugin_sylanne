"""Immutable W01 input for one installed C04 V3 association execution.

W01 records this inside the same Owner-fenced transaction as preparation.
Authority reads the frozen bytes; final adoption separately rechecks current
rights and graph heads after execution and independent cost settlement.
"""

from __future__ import annotations

from dataclasses import asdict
import json
import sqlite3

from ..authority_service.internal_work_contract import InternalWorkBindingV1
from ..domains.d04.interval_projection_v2 import D04IntervalProjectionPolicyV2
from ..domains.d04.joint_state_output_v1 import (
    joint_checkpoint_payload_v1, joint_state_payload_v1,
)
from ..graph_types import AtomKey
from ..native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_current_projection_service_v3 import issue_current_c04_targets_v3
from .c04_encoding_baseline_store_v3 import _receipt, read_c04_encoding_baseline_v3
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_v3_contracts import AssociationWorkInputV3
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise RuntimeError("C04 frozen input needs a caller-owned graph transaction")


def install_c04_frozen_association_original_v3(db: sqlite3.Connection) -> None:
    """Provision the immutable V3 row before W01's Owner transaction."""
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise RuntimeError("provision C04 V3 input before graph transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_c04_association_inputs_v3 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            binding_digest TEXT NOT NULL, input_digest TEXT NOT NULL,
            algorithm_build_digest TEXT NOT NULL, work_json TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            UNIQUE(bot,persona,binding_digest),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_c04_internal_work_prepared_v1(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_c04_association_input_no_update_v3
          BEFORE UPDATE ON graph_c04_association_inputs_v3
          BEGIN SELECT RAISE(ABORT, 'C04 V3 frozen input is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_c04_association_input_no_delete_v3
          BEFORE DELETE ON graph_c04_association_inputs_v3
          BEGIN SELECT RAISE(ABORT, 'C04 V3 frozen input is immutable'); END;
    """)


def verify_current_association_input_heads_v3(
    db: sqlite3.Connection, work: AssociationWorkInputV3,
) -> None:
    """Check exact positive/negative heads and every bounded edge page."""
    _transaction(db)
    if type(work) is not AssociationWorkInputV3:
        raise TypeError("typed C04 V3 work required")
    work.validate_closure()
    namespace = work.namespace
    for read in work.reads:
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?",
            (read.ref, *namespace.as_tuple),
        ).fetchone()
        if read.revision == 0:
            if row is not None:
                raise ValueError("frozen absent graph head appeared")
        elif row != (read.revision, read.value_json, int(read.valid)):
            raise ValueError("frozen graph original changed")
    # The V2 content closure reused by V3 excludes numeric checkpoints. Check
    # each condition's exact checkpoint against its adopted joint original.
    mood = next(read for read in work.reads if read.ref == work.mood_ref)
    mood_history = db.execute(
        "SELECT event_id,value,valid FROM graph_history WHERE token=? "
        "AND revision=? AND event_bot=? AND event_persona=?",
        (mood.ref, mood.revision, *namespace.as_tuple),
    ).fetchone()
    if mood_history is None or mood_history[1:] != (mood.value_json, 1):
        raise ValueError("frozen Mood lacks its adopted joint history")
    output = read_d04_joint_output_original_v1(db, namespace, mood_history[0])
    member = next((item for item in output.members
                   if item.predecessor_state_ref == mood.ref), None) if output else None
    if (member is None or member.predecessor_state_revision + 1 != mood.revision
            or canonical_digest(joint_state_payload_v1(member.next_state))
               != canonical_digest(mood.value)):
        raise ValueError("frozen Mood differs from its adopted joint output")
    receipt_digest = "sha256:" + canonical_digest(asdict(
        _receipt(db, namespace, mood_history[0])))
    for target in work.targets:
        condition = target.condition
        checkpoint = condition.current_checkpoint
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (checkpoint.ref, *namespace.as_tuple),
        ).fetchone()
        history = db.execute(
            "SELECT event_id,value,valid FROM graph_history WHERE token=? "
            "AND revision=? AND event_bot=? AND event_persona=?",
            (checkpoint.ref, checkpoint.revision, *namespace.as_tuple),
        ).fetchone()
        if (checkpoint.ref != member.checkpoint_ref
                or checkpoint.revision != member.predecessor_checkpoint_revision + 1
                or row is None or row[0] != checkpoint.revision or row[2] != 1
                or history != (mood_history[0], row[1], 1)
                or canonical_digest(json.loads(row[1])) != canonical_digest(
                    joint_checkpoint_payload_v1(member.next_checkpoint))
                or condition.current_joint_output_original_digest
                   != "sha256:" + output.original_digest
                or condition.current_joint_adoption_receipt_digest != receipt_digest):
            raise ValueError("frozen current checkpoint or joint adoption changed")
    for page in work.edge_pages:
        source = AtomKey.from_token(page.source_ref)
        rows = db.execute(
            "SELECT token FROM graph_atoms WHERE bot=? AND persona=? "
            "AND owner_kind='event' AND subject=? "
            "AND type_name='memory.association.v1' ORDER BY token LIMIT ?",
            (*namespace.as_tuple, source.owner.subject, work.budget.max_edges + 1),
        ).fetchall()
        actual = tuple(row[0] for row in rows)
        expected = page.edge_refs
        if page.next_after is None:
            if actual != expected:
                raise ValueError("frozen association page changed")
        elif (not expected or page.next_after != expected[-1]
              or actual[:len(expected)] != expected
              or len(actual) <= len(expected)):
            raise ValueError("frozen association continuation changed")


def _identity(namespace: NamespaceId, binding: InternalWorkBindingV1,
              work: AssociationWorkInputV3) -> None:
    from ..graph_coordinator import namespace_ref

    if (work.namespace != namespace or binding.namespace != namespace_ref(namespace)
            or (work.activity_id, work.operation_id)
               != (binding.activity_id, binding.operation_id)
            or work.algorithm_id != binding.algorithm_ref
            or work.algorithm_build_digest
               != "sha256:" + binding.algorithm_build_digest
            or work.input_digest != "sha256:" + binding.input_digest):
        raise ValueError("C04 V3 frozen input differs from prepared binding")


def record_c04_frozen_association_original_v3(
    db: sqlite3.Connection, namespace: NamespaceId,
    binding: InternalWorkBindingV1, work: AssociationWorkInputV3,
    *, asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> AssociationWorkInputV3:
    """Freeze authenticated target baselines and exact graph reads once."""
    _transaction(db)
    if (type(namespace) is not NamespaceId or
            type(binding) is not InternalWorkBindingV1 or
            type(work) is not AssociationWorkInputV3 or
            type(asset) is not D04LoadedTanhReadoutAsset or
            type(policy) is not D04IntervalProjectionPolicyV2):
        raise TypeError("typed C04 V3 namespace, binding and input required")
    _identity(namespace, binding, work)
    prepared = read_c04_internal_work_prepared_v1(db, namespace,
                                                  binding.operation_id)
    if prepared is None or prepared.binding != binding:
        raise ValueError("W01 prepared original differs")
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch != (work.graph_epoch,):
        raise ValueError("C04 V3 observation epoch changed")
    if (work.access_epoch, work.delete_epoch) != (prepared.access_epoch,
                                                  prepared.delete_epoch):
        raise ValueError("C04 V3 rights epoch differs from W01 preparation")
    verify_current_association_input_heads_v3(db, work)
    for target in work.targets:
        baseline = read_c04_encoding_baseline_v3(
            db, namespace=namespace,
            encoding_operation_id=target.baseline.encoding_operation_id,
            source_ref=target.source_ref,
        )
        if baseline.original != target.baseline:
            raise ValueError("C04 target has no adopted encoding-time baseline")
    mood = next(read for read in work.reads if read.ref == work.mood_ref)
    joint = db.execute(
        "SELECT event_id FROM graph_history WHERE token=? AND revision=?",
        (work.mood_ref, mood.revision),
    ).fetchone()
    if joint is None:
        raise ValueError("C04 current Mood joint origin is absent")
    issued = issue_current_c04_targets_v3(
        db, namespace=namespace, operation_id=work.operation_id,
        encoding_operations=tuple((target.source_ref,
                                   target.baseline.encoding_operation_id)
                                  for target in work.targets),
        mood_joint_operation_id=joint[0], mood_ref=work.mood_ref,
        audience=work.audience, purpose=work.purpose,
        owner_epoch=work.owner_epoch, access_epoch=work.access_epoch,
        delete_epoch=work.delete_epoch, asset=asset, policy=policy,
    )
    if issued != work.targets:
        raise ValueError("C04 input condition differs from D04 installed issuer")
    row = (binding.binding_digest, binding.input_digest,
           binding.algorithm_build_digest, work.to_json())
    key = (*namespace.as_tuple, binding.operation_id)
    prior = db.execute(
        "SELECT binding_digest,input_digest,algorithm_build_digest,work_json "
        "FROM graph_c04_association_inputs_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?", key,
    ).fetchone()
    if prior is not None:
        if prior != row:
            raise ValueError("C04 V3 frozen input changed on replay")
    else:
        db.execute("INSERT INTO graph_c04_association_inputs_v3 VALUES(?,?,?,?,?,?,?)",
                   (*key, *row))
    return work


def read_c04_frozen_association_original_v3(
    db: sqlite3.Connection, namespace: NamespaceId,
    binding: InternalWorkBindingV1,
) -> AssociationWorkInputV3 | None:
    """Read immutable W01 bytes for Authority's one-time execution."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(binding) is not InternalWorkBindingV1:
        raise TypeError("typed C04 V3 namespace and binding required")
    row = db.execute(
        "SELECT binding_digest,input_digest,algorithm_build_digest,work_json "
        "FROM graph_c04_association_inputs_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, binding.operation_id),
    ).fetchone()
    if row is None:
        return None
    work = AssociationWorkInputV3.from_json(row[3])
    prepared = read_c04_internal_work_prepared_v1(db, namespace,
                                                  binding.operation_id)
    _identity(namespace, binding, work)
    if (prepared is None or prepared.binding != binding or
            row[:3] != (binding.binding_digest, binding.input_digest,
                        binding.algorithm_build_digest)):
        raise ValueError("C04 V3 frozen original identity changed")
    for target in work.targets:
        baseline = read_c04_encoding_baseline_v3(
            db, namespace=namespace,
            encoding_operation_id=target.baseline.encoding_operation_id,
            source_ref=target.source_ref,
        )
        if baseline.original != target.baseline:
            raise ValueError("C04 V3 frozen baseline original changed")
    return work


__all__ = [
    "install_c04_frozen_association_original_v3",
    "record_c04_frozen_association_original_v3",
    "read_c04_frozen_association_original_v3",
    "verify_current_association_input_heads_v3",
]
