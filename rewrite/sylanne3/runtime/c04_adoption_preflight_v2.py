"""Current, read-only C04 adoption gate after independent cost settlement.

This does not issue D04 feeling evidence or create D06/D07 experience writes.
Those require an installed verified projection and a later W01 graph CAS.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
from ..graph_types import AtomKey, GraphWrite
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_frozen_association_original_v2 import (
    read_c04_frozen_association_original_v2,
)
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1


class C04AdoptionHold(ValueError):
    """Original cost, graph, or semantic facts do not authorize adoption."""


@dataclass(frozen=True, slots=True)
class C04AdoptionPreflightV2:
    namespace: NamespaceId
    operation_id: str
    binding_digest: str
    input_digest: str
    proof_digest: str
    body_settlement_ref: str
    graph_epoch: int
    status: str = "candidate_hold_verified_d04_salience_and_final_cas"


def inspect_current_c04_adoption_v2(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    *, installed_algorithm_build_digest: str,
) -> C04AdoptionPreflightV2:
    """Reread originals and exact current heads in the caller's graph read tx."""
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(operation_id) is not str or not operation_id
            or type(installed_algorithm_build_digest) is not str
            or len(installed_algorithm_build_digest) != 64):
        raise C04AdoptionHold("installed C04 algorithm/current transaction unavailable")
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    if prepared is None:
        raise C04AdoptionHold("executable C04 prepared original absent")
    binding = prepared.binding
    if binding.algorithm_build_digest != installed_algorithm_build_digest:
        raise C04AdoptionHold("C04 installed algorithm build differs")
    work = read_c04_frozen_association_original_v2(db, namespace, binding)
    if work is None or work.input_digest != "sha256:" + binding.input_digest:
        raise C04AdoptionHold("C04 frozen semantic input absent")
    cpu = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
    body = read_c04_body_cost_original_v1(db, namespace, operation_id)
    if (cpu is None or body is None
            or cpu.binding_digest != binding.binding_digest
            or cpu.prepared_digest != prepared.prepared_digest
            or cpu.status != "completed"
            or cpu.budget_receipt_status != "settled"
            or not cpu.component_completed
            or body.binding_digest != binding.binding_digest
            or body.proof_digest != cpu.proof_digest
            or body.component_receipt_ref == ""
            or (body.state_ref, body.reservation_ref) !=
               (prepared.body_state_ref, binding.body_reservation_ref)):
        raise C04AdoptionHold("independent settled C04 cost originals unavailable")
    expected = (
        (body.state_ref, "d02.body_state.v1", prepared.body_state_revision + 1),
        (body.reservation_ref, "d02.reservation.v1",
         prepared.body_reservation_revision + 1),
        (body.settlement_ref, "d02.settlement.v1", 1),
    )
    writes = []
    for ref, type_name, revision in expected:
        key = AtomKey.from_token(ref)
        if ((key.owner.bot, key.owner.persona) != namespace.as_tuple
                or key.type_name != type_name):
            raise C04AdoptionHold("C04 body graph reference differs")
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
        ).fetchone()
        history = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_id=?",
            (ref, revision, *namespace.as_tuple, operation_id),
        ).fetchone()
        if (row is None or row[0] != revision or row[2] != 1
                or history != (row[1], 1)):
            raise C04AdoptionHold("C04 body cost graph head or history changed")
        writes.append(GraphWrite(key, json.loads(row[1])))
    if canonical_digest(tuple(writes)) != body.writes_digest:
        raise C04AdoptionHold("C04 body cost graph values differ")
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch is None:
        raise C04AdoptionHold("C04 graph epoch unavailable")
    return C04AdoptionPreflightV2(
        namespace, operation_id, binding.binding_digest,
        work.input_digest, cpu.proof_digest, body.settlement_ref, epoch[0],
    )


__all__ = ["C04AdoptionHold", "C04AdoptionPreflightV2",
           "inspect_current_c04_adoption_v2"]
