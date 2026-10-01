"""Current original allocation reads and exact once-only D04 consumption writes."""
from __future__ import annotations
from dataclasses import asdict
import json
from ..domains.d04.contribution_ledger_v3 import contribution_ledger_key_v3, D04ContributionConsumptionV3
from ..graph_types import GraphWrite
from ..runtime_contracts import canonical_serialize
from .d04_semantic_mapping_v3 import read_d04_mapping_acceptance_v3


def current_contribution_allocations_v3(db, namespace, drives):
    refs = sorted({drive.mapping_compiler_ref for drive in drives})
    result = {}
    for ref in refs:
        original = read_d04_mapping_acceptance_v3(db, namespace, ref)
        if original is None:
            raise ValueError("D04 consumption lacks its actual mapping original")
        raw, digest = original
        for family in raw["family_candidates"]:
            for allocation in family["contribution_allocations"]:
                key = contribution_ledger_key_v3(namespace, family["family_root"], allocation["event_ref"],
                    allocation["contribution_key"], allocation["facet_id"])
                value = {"family_root": family["family_root"], **allocation, "mapping_ref": ref, "mapping_digest": digest,
                    "role_start": family["time_map"]["role_start"], "role_end": family["time_map"]["role_end"]}
                if key in result and canonical_serialize(result[key]) != canonical_serialize(value):
                    raise ValueError("D04 contribution identity has conflicting allocations")
                result[key] = value
    if not result:
        raise ValueError("D04 numeric advance has no authenticated contribution allocation")
    return tuple(sorted(result.items(), key=lambda item: item[0].token))


def current_contribution_writes_v3(db, namespace, drives, *, operation_id, numeric_binding_digest, output_original_digest):
    writes = []
    for key, raw in current_contribution_allocations_v3(db, namespace, drives):
        # Invalidated rows still record consumed reality. A correction can
        # suppress a contribution; it must never make the same dose spendable.
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone():
            raise ValueError("D04 event contribution was already consumed")
        value = D04ContributionConsumptionV3(**{**raw,
            "contribution_dose": tuple(raw["contribution_dose"]),
            "block_shares": tuple(tuple(pair) for pair in raw["block_shares"]),
            "operation_id": operation_id, "numeric_binding_digest": numeric_binding_digest,
            "output_original_digest": output_original_digest})
        writes.append(GraphWrite(key, json.loads(canonical_serialize(asdict(value)))))
    return tuple(writes)
