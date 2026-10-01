"""Read authenticated typed recovery facts without recreating execution bodies."""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_storage_transition_v1 import C09ExecutionBindingV1, C09RecoveryBindingsV1, VerifiedSanitizedExecutionReadV4
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import InstalledC09StorageReaderV1
from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked, read_execution_recovery_facts_pin_v4_locked


def read_recovery_bindings_v1_locked(db,*,namespace,operation_id):
    row = db.execute("SELECT bindings_json,bindings_digest FROM authority_c09_recovery_bindings_v1 WHERE namespace=? AND operation_id=?",(namespace,operation_id)).fetchone()
    if row is None:
        return None
    body = json.loads(row[0])
    body["prior_fact_frame_digests"] = tuple(body["prior_fact_frame_digests"])
    bindings = []
    for value in body["execution_bindings"]:
        for name in ("source_row_commitments","d02_quote_ids","d02_component_ids","d11_settlement_ids"):
            value[name] = tuple(value[name])
        bindings.append(C09ExecutionBindingV1(**value))
    body["execution_bindings"] = tuple(bindings)
    result = C09RecoveryBindingsV1(**body)
    if row != (canonical_serialize(asdict(result)),result.bindings_digest):
        raise AuthorityUnavailable("C09 typed bindings original differs")
    return result


class InstalledSanitizedRecoveryResolverV4:
    def __init__(self, *, storage_reader):
        if not isinstance(storage_reader,InstalledC09StorageReaderV1):
            raise AuthorityUnavailable("installed C09 recovery storage reader required")
        self.reader = storage_reader

    def read_verified_frames_v4(self):
        context = self.reader.read_verified_current_storage_v1()
        if context.prepared_original is None:
            return context,()
        member = next(m for m in context.manifest["members"] if m["role"] == "core")
        frames = []
        with self.reader._db() as control:
            self.reader._current(control)
            operations = tuple(control.execute("SELECT prepared_original_json FROM c09_storage_operations_v1 WHERE installation_id=? AND generation<=? ORDER BY generation", (self.reader.installation_id,context.storage_generation)))
        with closing(sqlite3.connect(Path(member["resolved_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
            prior_root = None
            for row in operations:
                original = json.loads(row[0]); self.reader.verify_original_v1(original,"prepared_digest")
                namespace,operation = original["namespace"],original["operation_id"]
                facts = read_execution_recovery_facts_v4_locked(db,namespace,operation_id=operation)
                pin = read_execution_recovery_facts_pin_v4_locked(db,namespace,operation_id=operation)
                bindings = read_recovery_bindings_v1_locked(db,namespace=namespace,operation_id=operation)
                if (facts is None or pin is None or bindings is None
                        or original["facts_digest"] != facts.facts_digest or original["facts_pin_original"] != asdict(pin)
                        or original["recovery_bindings_digest"] != bindings.bindings_digest):
                    raise AuthorityUnavailable("C09 authenticated recovery frame differs")
                if bindings.prior_transition_digest_or_none != prior_root:
                    raise AuthorityUnavailable("C09 recovery transition lineage differs")
                from .c09_model_budget_original_v1 import read_model_budget_originals_v1, model_unit_fact_v4
                models = read_model_budget_originals_v1(db, namespace=namespace, operation_id=operation)
                model_bindings = {item.execution_id: item for item in bindings.execution_bindings if item.execution_kind == "model"}
                if set(model_bindings) != {item.call_id for item in models}:
                    raise AuthorityUnavailable("C09 model obligation inventory differs from authenticated bindings")
                execution_facts = {item.execution_id: item for item in facts.executions}
                unit_facts = {item.settlement_id: item for item in facts.d11_facts}
                for model in models:
                    binding = model_bindings[model.call_id]
                    fact = execution_facts.get(model.call_id)
                    expected_units = tuple(model_unit_fact_v4(model, unit) for unit in model.units if unit.actual_or_none is not None)
                    if (fact is None or fact.signature_commitment != model.original_digest
                            or fact.input_commitment != model.request_digest
                            or fact.terminal_commitment != model.terminal_digest_or_none
                            or binding.business_operation_id != model.model_operation_id
                            or binding.originating_journal_id != model.originating_journal_id
                            or binding.source_row_commitments != tuple(sorted({*model.source_row_commitments, model.original_digest}))
                            or binding.d11_settlement_ids != tuple(sorted(item.settlement_id for item in expected_units))
                            or any(unit_facts.get(item.settlement_id) != item for item in expected_units)):
                        raise AuthorityUnavailable("C09 model original is not pinned by actual signed facts/binding")
                    if db.execute("SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?", (model.call_id,)).fetchone():
                        raise AuthorityUnavailable("C09 consumed model response body survives")
                    for kind, item_id in (("model_call", model.call_id), ("model_operation", model.model_operation_id),
                            ("model_job", model.job_id), ("model_acquire", model.acquire_operation_id),
                            ("model_admission", model.admission_id_or_none)):
                        if item_id is not None and db.execute("SELECT original_commitment FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind=? AND item_id=?",
                                (namespace, kind, item_id)).fetchone() != (model.original_digest,):
                            raise AuthorityUnavailable("C09 actual model once-only consumption differs")
                prior_root = original["prepared_digest"]
                frames.append((original,facts,bindings))
        context.require_current("maintenance")
        return context,tuple(frames)

    def read_sanitized_model_budget_v1(self, *, namespace, call_id):
        context, frames = self.read_verified_frames_v4()
        from .c09_model_budget_original_v1 import read_model_budget_originals_v1
        member = next(item for item in context.manifest["members"] if item["role"] == "core")
        found = None
        with closing(sqlite3.connect(Path(member["resolved_path"]).as_uri() + "?mode=ro", uri=True)) as db:
            for original, _facts, _bindings in frames:
                for model in read_model_budget_originals_v1(db, namespace=namespace, operation_id=original["operation_id"]):
                    if model.call_id == call_id:
                        if found is not None and found != model:
                            raise AuthorityUnavailable("C09 model obligation repeated-frame conflict")
                        found = model
        context.require_current("accounting")
        return found

    def read_sanitized_execution_v4(self, *, namespace, execution_id):
        context,frames = self.read_verified_frames_v4()
        found, binding, unknown = None,None,None
        d02,d11,chain = {},{},[]
        for original,facts,bindings in frames:
            if facts.namespace != namespace:
                raise AuthorityUnavailable("C09 recovery namespace differs")
            chain.append(original["prepared_digest"])
            for fact in facts.executions:
                if fact.execution_id == execution_id:
                    if found is not None and found != fact:
                        raise AuthorityUnavailable("C09 historical execution fact conflict")
                    found = fact
            for candidate in bindings.execution_bindings:
                if candidate.execution_id == execution_id:
                    if binding is not None and binding != candidate:
                        raise AuthorityUnavailable("C09 historical business binding conflict")
                    binding = candidate
            for fact in facts.unknown_facts:
                if fact.execution_id == execution_id:
                    if unknown is not None and unknown != fact:
                        raise AuthorityUnavailable("C09 historical unknown footprint conflict")
                    unknown = fact
            for fact in facts.d02_facts:
                key = fact.quote_id,fact.component_id,fact.outcome_id,fact.settlement_id
                if key in d02 and d02[key] != fact:
                    raise AuthorityUnavailable("C09 D02 settlement identity conflict")
                d02[key] = fact
            for fact in facts.d11_facts:
                key = fact.parent_budget_id,fact.idempotency_id,fact.settlement_id
                if key in d11 and d11[key] != fact:
                    raise AuthorityUnavailable("C09 D11 settlement identity conflict")
                d11[key] = fact
        if found is None:
            return None
        if binding is None or binding.input_commitment != found.input_commitment:
            raise AuthorityUnavailable("C09 verified business operation binding absent")
        return VerifiedSanitizedExecutionReadV4(execution_id,binding.business_operation_id,
            found.status,found.input_commitment,found.result_commitment,found.terminal_commitment,found.consumed,
            tuple(v for _,v in sorted(d02.items()) if v.quote_id in binding.d02_quote_ids and v.component_id in binding.d02_component_ids),
            tuple(v for _,v in sorted(d11.items()) if v.settlement_id in binding.d11_settlement_ids),
            None if unknown is None else unknown.footprint,binding.originating_journal_id,tuple(chain))

    def read_merged_facts_v4(self):
        _context,frames = self.read_verified_frames_v4()
        groups = {name:{} for name in ("executions","d02_facts","d11_facts","unknown_facts","graph_facts")}
        for _original,facts,_bindings in frames:
            for name,key_field in (("executions","execution_id"),("d02_facts","quote_id"),
                    ("d11_facts","settlement_id"),("unknown_facts","execution_id"),("graph_facts","operation_id")):
                for item in getattr(facts,name):
                    key = getattr(item,key_field)
                    if key in groups[name] and groups[name][key] != item:
                        raise AuthorityUnavailable("C09 prior facts exact conflict: " + name)
                    groups[name][key] = item
        return SimpleNamespace(**{name:tuple(v for _,v in sorted(items.items())) for name,items in groups.items()})
