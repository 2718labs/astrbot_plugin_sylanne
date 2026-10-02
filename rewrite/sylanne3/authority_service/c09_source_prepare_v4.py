"""Freeze and authenticate a V1/V2 source or a verified V4 prefix plus suffix."""
from __future__ import annotations

from dataclasses import asdict
from contextlib import ExitStack
import json

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .c09_recovery_frame_v4 import make_source_seal_v4, make_source_pin_v4, make_fact_frame_v4, C09ExecutionSourceSealV4
from .c09_originals_archive_v1 import install_c09_archive_schema_v1
from .erasure_closure_inventory import CleanupRunV2, _TABLES
from .erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked, read_execution_recovery_facts_v4_locked
from .v2_execution_journal import AuthorityV2ExecutionJournal


def _accepted(core,closure,subject,operation_id):
    with core._tx() as db:
        run = closure._read_record(db,_TABLES[1],operation_id,CleanupRunV2)
        if run is None:
            raise AuthorityUnavailable("accepted C09 cleanup run absent")
        receipt = closure._accepted_locked(db,run,subject)
        return run,receipt


def prepare_installed_execution_source_v4(*,core,closure,credential,subject,operation_id):
    core._require(credential,"execution_redaction_install",closure.namespace)
    reader = getattr(core,"_c09_storage_reader_v1",None)
    if reader is None:
        raise AuthorityUnavailable("installed C09 control verifier required")
    intent = reader.read_operation_event_v1(operation_id,"INTENT")
    context = reader.read_verified_current_storage_v1()
    if intent["pointer_version"] != context.pointer_version or context.stage != "INTENT":
        raise AuthorityUnavailable("C09 source seal requires current INTENT")
    run,accepted = _accepted(core,closure,subject,operation_id)
    port = core._execution_recovery_facts_ports_v4.get(closure.namespace)
    if port is None:
        raise AuthorityUnavailable("installed C09 recovery readers absent")
    source = closure.execution
    owned = False
    # A legacy V3 seal is immutable and still blocks ordinary V1/V2 opening.
    if getattr(source,"_installed_storage_reader",None) is None:
        with core._tx() as db:
            from .erasure_closure_redaction_v3 import read_execution_redaction_seal_locked
            legacy = read_execution_redaction_seal_locked(db,closure.namespace)
        if legacy is not None:
            source = AuthorityV2ExecutionJournal.open_prepared_redaction_v3(source.path,
                namespace=closure.namespace,journal_id=legacy.execution_journal_id,core=core,credential=credential)
            owned = True
    try:
        with ExitStack() as stack:
            stack.enter_context(closure.deletion.freeze_writes())
            if source._maintenance_seal_digest is not None:
                rows = stack.enter_context(source.freeze_prepared_redaction_v3())
                head, _ = source._scan_locked()
            else:
                stack.enter_context(source.freeze_writes())
                head, rows = source._scan_locked()
                rows = tuple(rows)
            signed = core._verify_execution_redaction_c04_rows(source,rows,journal_id=head.journal_id)
            prefix = None
            if source._schema_version == "4":
                if context.prepared_original is None:
                    raise AuthorityUnavailable("C09 prior authenticated prefix absent")
                prefix = canonical_digest(tuple(source._db.execute("SELECT * FROM authority_v2_execution_redacted_prefix_v4").fetchone()))
            seal, verifier = derive_execution_source_seal_v4(context=context,
                installation_id=closure.installation_id, namespace=closure.namespace,
                operation_id=operation_id, head=head, rows=rows, prefix=prefix, run=run, signed=signed)
            with port.freeze_verified_originals_v4(seal=seal,old=source,rows=rows,verifier_commitment=verifier):
                reads = {name:getattr(port,"read_current_"+method+"_originals_v4")(
                    namespace=closure.namespace,operation_id=operation_id)
                    for name,method in (("executions","execution"),("d02_facts","d02"),
                        ("d11_facts","d11"),("unknown_facts","unknown"),("graph_facts","graph"))}
                facts, pin = _derive_actual_contact_complete_frame_v5(port, context=context, seal=seal,
                    verifier=verifier, reads=reads)
        with core._tx() as db:
            persist_execution_source_bundle_in_tx_v4(db, seal=seal, pin=pin, facts=facts)
        return dict(seal=seal,pin=pin,facts=facts,rows=rows,accepted_receipt=accepted,run=run)
    finally:
        if owned:
            source.close()


def read_installed_source_bundle_v4(*,core,closure,credential,subject,operation_id):
    core._require(credential,"execution_redaction_install",closure.namespace)
    run,accepted = _accepted(core,closure,subject,operation_id)
    with closure.execution._transaction():
        with core._tx() as db:
            return read_execution_source_bundle_in_tx_v4(db, execution_db=closure.execution._db,
                namespace=closure.namespace, operation_id=operation_id, run=run, accepted=accepted)


def persist_execution_source_bundle_in_tx_v4(db, *, seal, pin, facts):
    """Exact insert/replay of the three originals in the real source Core transaction."""
    if not db.in_transaction:
        raise AuthorityUnavailable("C09 source originals need pinned Core transaction")
    operation_id = seal.operation_id
    install_c09_archive_schema_v1(db)
    for table,column,digest_column,value in (
            ("authority_c09_execution_source_seals_v4","seal_json","seal_digest",seal),
            ("authority_c09_execution_source_pins_v4","pin_json","pin_digest",pin),
            ("authority_c09_recovery_fact_frames_v4","facts_json","facts_digest",facts)):
        encoded = canonical_serialize(asdict(value))
        row = db.execute(f"SELECT {column},{digest_column} FROM {table} WHERE namespace=? AND operation_id=?", (seal.namespace,operation_id)).fetchone()
        expected = (encoded,getattr(value,digest_column))
        if row is not None and row != expected:
            raise AuthorityUnavailable("C09 source original exact replay differs")
        if row is None:
            db.execute(f"INSERT INTO {table} VALUES(?,?,?,?)",(seal.namespace,operation_id,*expected))


def read_execution_source_bundle_in_tx_v4(db, *, execution_db, namespace, operation_id, run, accepted):
    """Read signed source originals and exact suffix under real pinned transactions."""
    if not db.in_transaction or not execution_db.in_transaction:
        raise AuthorityUnavailable("C09 source bundle needs pinned Core/execution snapshots")
    row = db.execute("SELECT seal_json FROM authority_c09_execution_source_seals_v4 WHERE namespace=? AND operation_id=?",(namespace,operation_id)).fetchone()
    if row is None:
        raise AuthorityUnavailable("C09 versioned source seal absent")
    body = json.loads(row[0]); body["suffix_row_commitments"] = tuple(body["suffix_row_commitments"])
    seal = C09ExecutionSourceSealV4(**body)
    pin = read_execution_recovery_facts_pin_v4_locked(db,namespace,operation_id=operation_id)
    facts = read_execution_recovery_facts_v4_locked(db,namespace,operation_id=operation_id)
    if pin is None or facts is None or pin.seal_digest != seal.seal_digest or seal.accepted_receipt_digest != run.accepted_receipt_digest:
        raise AuthorityUnavailable("C09 source pin/accepted original differs")
    rows = tuple(execution_db.execute("SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest FROM authority_v2_execution_entries ORDER BY seq"))
    commitments = tuple(canonical_digest((r[0],r[1],r[2],r[3],r[5],r[6],__import__('hashlib').sha256(r[4]).hexdigest())) for r in rows)
    if commitments != seal.suffix_row_commitments:
        raise AuthorityUnavailable("C09 frozen suffix differs from installed source seal")
    return dict(seal=seal,pin=pin,facts=facts,rows=rows,accepted_receipt=accepted,run=run)


def derive_execution_source_seal_v4(*, context, installation_id, namespace,
        operation_id, head, rows, prefix, run, signed):
    commitments = tuple(canonical_digest((r[0], r[1], r[2], r[3], r[5], r[6],
        __import__('hashlib').sha256(r[4]).hexdigest())) for r in rows)
    seal = make_source_seal_v4(authority_id=context.manifest["authority_id"], installation_id=installation_id,
        namespace=namespace, operation_id=operation_id, execution_journal_id=head.journal_id,
        execution_seq=head.seq, execution_digest=head.digest, prior_prefix_digest=prefix,
        suffix_row_commitments=commitments, accepted_receipt_digest=run.accepted_receipt_digest)
    verifier = canonical_digest(("sylanne3.c09.installed_source_verifier.v4", seal.seal_digest, signed,
        None if context.prepared_original is None else context.prepared_original["prepared_digest"]))
    return seal, verifier


def derive_execution_source_fact_frame_v4(*, context, seal, verifier, reads):
    facts = make_fact_frame_v4(authority_id=seal.authority_id, installation_id=seal.installation_id,
        namespace=seal.namespace, operation_id=seal.operation_id, old_journal_id=seal.execution_journal_id,
        old_seq=seal.execution_seq, old_chain_head_digest=seal.execution_digest,
        prior_fact_frame_digests=() if context.prepared_original is None else (context.prepared_original["facts_digest"],),
        verifier_commitment=verifier, **reads)
    return facts, make_source_pin_v4(seal=seal, facts=facts)


def _derive_actual_contact_complete_frame_v5(port, *, context, seal, verifier, reads):
    from .c09_recovery_frame_v5 import _issue_contact_finish_inventory_v5, _make_issued_frame_v5
    from .c09_contact_finish_original_v1 import INVENTORY_PREFIX
    reads = dict(reads)
    reads['graph_facts'] = tuple(fact for fact in reads['graph_facts'] if not fact.operation_id.startswith(INVENTORY_PREFIX))
    ordinary, _old_pin = derive_execution_source_fact_frame_v4(context=context, seal=seal, verifier=verifier, reads=reads)
    inventory = _issue_contact_finish_inventory_v5(port, namespace=seal.namespace, operation_id=seal.operation_id)
    facts, pin = _make_issued_frame_v5(port, ordinary_facts=ordinary, inventory=inventory, seal=seal)
    from .c09_contact_frame_authentication_v1 import _issue_authenticated_contact_frames_v1
    _issue_authenticated_contact_frames_v1(port, facts=facts, pin=pin)
    from .c09_contact_carrier_inventory_v2 import _capture_issued_contact_carriers_v2
    _capture_issued_contact_carriers_v2(port, inventory=inventory)
    return facts, pin


def prepare_execution_source_connections_v4(*, core_db, business_db, execution_reader,
        config, control, operation_id, run, accepted):
    """Recompute all installed source originals before exact insertion or replay."""
    from .c09_current_recovery_originals_v4 import ConnectionC09RecoveryOriginalsV4
    from .c09_connection_state_v1 import authority_id_in_tx_v1
    context = control.read_verified_current_storage_v1(verify_files=False)
    intent = control.read_operation_event_v1(operation_id, "INTENT")
    if (context.stage != "INTENT" or intent["pointer_version"] != context.pointer_version
            or authority_id_in_tx_v1(core_db) != control.authority_id
            or canonical_digest(accepted) != run.accepted_receipt_digest
            or intent["details"]["accepted_receipt_digest"] != run.accepted_receipt_digest):
        raise AuthorityUnavailable("C09 actual source INTENT/accepted identity differs")
    head, raw = execution_reader.read_verified_rows_v1()
    rows = tuple(raw)
    port = ConnectionC09RecoveryOriginalsV4(config=config, control=control, core_db=core_db,
        business_db=business_db, execution_reader=execution_reader, rows=rows)
    try:
        port._completed_core = control.read_build_original_v1(operation_id=operation_id, kind="file_core") is not None
        signed = port.verify_execution_rows_v1()
        prefix = None if execution_reader._schema_version != "4" else canonical_digest(tuple(
            execution_reader._db.execute("SELECT * FROM authority_v2_execution_redacted_prefix_v4").fetchone()))
        seal, verifier = derive_execution_source_seal_v4(context=context, installation_id=control.installation_id,
            namespace=execution_reader.namespace, operation_id=operation_id, head=head, rows=rows,
            prefix=prefix, run=run, signed=signed)
        with port.freeze_verified_connection_originals_v4(seal=seal, verifier_commitment=verifier):
            reads = {name: getattr(port, "read_current_" + method + "_originals_v4")(
                namespace=execution_reader.namespace, operation_id=operation_id)
                for name, method in (("executions", "execution"), ("d02_facts", "d02"),
                    ("d11_facts", "d11"), ("unknown_facts", "unknown"), ("graph_facts", "graph"))}
            facts, pin = _derive_actual_contact_complete_frame_v5(port, context=context, seal=seal, verifier=verifier, reads=reads)
        completed_core = control.read_build_original_v1(operation_id=operation_id, kind="file_core")
        if completed_core is not None:
            for table, column, value in (("authority_c09_execution_source_seals_v4", "seal_json", seal),
                    ("authority_c09_execution_source_pins_v4", "pin_json", pin),
                    ("authority_c09_recovery_fact_frames_v4", "facts_json", facts)):
                if core_db.execute(f"SELECT {column} FROM {table} WHERE namespace=? AND operation_id=?",
                        (seal.namespace, operation_id)).fetchone() != (canonical_serialize(asdict(value)),):
                    raise AuthorityUnavailable("C09 completed Core candidate forbids new source originals")
        persist_execution_source_bundle_in_tx_v4(core_db, seal=seal, pin=pin, facts=facts)
        return dict(seal=seal, pin=pin, facts=facts, rows=rows, accepted_receipt=accepted, run=run,
            _contact_finish_scope=port._contact_finish_scope,
            _life_completed_scope=port._life_completed_scope)
    except BaseException:
        from .c09_contact_finish_original_v1 import _revoke_contact_finish_scope_v1
        _revoke_contact_finish_scope_v1(port)
        from .c09_life_completed_archive_v1 import revoke_completed_life_scope_v1
        revoke_completed_life_scope_v1(port)
        raise
