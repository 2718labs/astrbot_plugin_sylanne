"""Installed one-claim source-note driver and explicit lost-ACK recovery."""
from dataclasses import dataclass

from ..runtime_contracts import NamespaceId
from ..host.d11_life_port_v1 import InstalledD11LifePortV1
from ..host.v2_fence_port import V2FencePort, V2FenceOutcomeUnknown
from .d11_life_preparation_v1 import read_prepared_life_by_ref_v1
from .d11_life_adoption_v1 import _adopt_legacy_current_life_v1


@dataclass(frozen=True, slots=True)
class LifeExecutionProgressV1:
    prepared_original_ref: str
    claim: object
    terminal: object
    adoption: object
    state: str


def run_prepared_source_note_v1(graph, bootstrap, *, namespace, prepared_original_ref):
    from .current_character_labor_adoption_v1 import begin_current_character_labor_execution_entry_v1
    return begin_current_character_labor_execution_entry_v1(
        graph, bootstrap, namespace=namespace,
        prepared_original_ref=prepared_original_ref)


def _run_legacy_prepared_source_note_v1(graph, bootstrap, *, namespace, prepared_original_ref):
    graph._admin(bootstrap)
    port = getattr(graph, "_GraphCoordinator__content_fence_v2", None)
    if type(port) is not V2FencePort or type(namespace) is not NamespaceId:
        raise TypeError("Life driver requires actual installed Graph and paired fence port")
    installed = InstalledD11LifePortV1(port)
    store = graph._GraphCoordinator__store
    with store._lock:
        db=store._db
        if db.in_transaction:
            raise ValueError("Life execution starts outside all Graph transactions")
        db.execute("BEGIN")
        try:
            from .d11_life_preparation_v1 import TABLE
            kinds=db.execute("SELECT kind FROM " + TABLE +
                " WHERE bot=? AND persona=? AND original_ref=? "
                "AND kind IN ('prepared','character_labor_prepared_v1') ORDER BY kind LIMIT 2",
                (*namespace.as_tuple,prepared_original_ref)).fetchall()
            if kinds != [("prepared",)]:
                raise ValueError("legacy Life driver requires the unique actual old Prepared header")
            prepared=read_prepared_life_by_ref_v1(db, namespace=namespace, prepared_original_ref=prepared_original_ref,
                issuer=graph._GraphCoordinator__d11_issuer)
        finally:
            db.execute("ROLLBACK")
    if prepared is None:
        raise ValueError("Life driver has no genuine committed preparation")
    binding=prepared.binding
    from .d11_life_contract_v1 import D11LifeExecutionBindingV1
    read_original=(installed.read_own_d11_life_execution_original_v1
        if type(binding)is D11LifeExecutionBindingV1 else installed.read_own_d11_draft_execution_original_v1)
    claim,terminal=read_original(binding=binding)
    if claim is None:
        try:
            claim,terminal=installed.execute_d11_life_v1(binding=binding)
        except V2FenceOutcomeUnknown:
            claim,terminal=read_original(binding=binding)
            if claim is None:
                return LifeExecutionProgressV1(prepared_original_ref,None,None,None,"execution_ack_unknown")
    if terminal is None:
        claim,terminal=installed.recover_claimed_d11_life_v1(binding=binding)
    if terminal is None:
        return LifeExecutionProgressV1(prepared_original_ref,claim,None,None,"claimed_waiting_actual_executor")
    adoption=_adopt_legacy_current_life_v1(graph,bootstrap,namespace=namespace,prepared_original_ref=prepared_original_ref)
    return LifeExecutionProgressV1(prepared_original_ref,claim,terminal,adoption,"adopted_"+terminal.status)
