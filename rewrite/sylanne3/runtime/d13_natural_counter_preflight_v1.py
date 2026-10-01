"""Non-authorizing Host count between two short fenced Graph transactions.

The complete source pair is transient. Only its content-free signed count
original is imported in the final transaction, which must regenerate and
validate the pair at the new trusted time before any selection/activation.
"""
from __future__ import annotations
from dataclasses import dataclass
import json

from ..authority_service.d13_installed_counter_v1 import InstalledD13CounterCommandV1
from ..authority_service.d13_wire_evidence_v1 import (
    d13_full_wire_count_request_v1, record_signed_d13_wire_evidence_v1,
    verify_signed_d13_wire_envelope_v1,
)
from ..runtime_contracts import canonical_digest, canonical_serialize
from .installed_d13_natural_frame_v4 import D13NaturalWirePreflightV1


@dataclass(frozen=True, slots=True)
class D13CountedNaturalPreflightV1:
    preflight: D13NaturalWirePreflightV1
    envelope_json: str
    status: str = "non_authorizing_count_result"

    def __post_init__(self):
        if (type(self.preflight) is not D13NaturalWirePreflightV1
                or self.status != "non_authorizing_count_result"
                or type(self.envelope_json) is not str
                or len(self.envelope_json.encode()) > 65536
                or canonical_serialize(json.loads(self.envelope_json)) != self.envelope_json):
            raise ValueError("D13 count result requires exact non-authorizing preflight bytes")

    @property
    def evidence_digest(self):
        return canonical_digest(json.loads(self.envelope_json))


def count_installed_d13_preflight_v1(db, *, graph_lock, bundle, preflight):
    """Run only the protected installed counter, outside SQL and Graph lock."""
    from ..host.authority_profile import AdminInstallationBundle
    if (db.in_transaction or graph_lock._is_owned()
            or type(bundle) is not AdminInstallationBundle
            or type(preflight) is not D13NaturalWirePreflightV1
            or type(bundle.d13_wire_counter) is not InstalledD13CounterCommandV1
            or bundle.d13_wire_policy is None
            or bundle.installation_policy.namespace != preflight.raw.input.plan.namespace
            or bundle.d13_wire_policy.policy_digest != preflight.installed_policy_digest):
        raise ValueError("D13 count needs installed authority, transient pair and no Graph lock/transaction")
    request = d13_full_wire_count_request_v1(policy=bundle.d13_wire_policy,
        raw=preflight.raw, compressed=preflight.compressed,
        current_window=preflight.current_window, standby=preflight.standby,
        precompression_plan=preflight.precompression_plan)
    envelope = bundle.d13_wire_counter.count_outside_graph_transaction_v1(
        db=db, policy=bundle.d13_wire_policy, request=request)
    return D13CountedNaturalPreflightV1(preflight, canonical_serialize(envelope))


def record_counted_d13_preflight_v1(db, *, bundle, counted):
    """Import inside the final fenced transaction; this grants no selection."""
    from ..host.authority_profile import AdminInstallationBundle
    if (not db.in_transaction or type(bundle) is not AdminInstallationBundle
            or type(counted) is not D13CountedNaturalPreflightV1
            or bundle.d13_wire_policy is None
            or counted.preflight.raw.input.plan.namespace != bundle.installation_policy.namespace
            or bundle.d13_wire_policy.policy_digest != counted.preflight.installed_policy_digest):
        raise ValueError("D13 count import requires same installed namespace/policy and fenced transaction")
    envelope = json.loads(counted.envelope_json)
    payload = verify_signed_d13_wire_envelope_v1(bundle.d13_wire_policy, envelope)
    request = d13_full_wire_count_request_v1(policy=bundle.d13_wire_policy,
        raw=counted.preflight.raw, compressed=counted.preflight.compressed,
        current_window=counted.preflight.current_window, standby=counted.preflight.standby,
        precompression_plan=counted.preflight.precompression_plan)
    if any(payload.get(k) != v for k, v in request["original"].items()):
        raise ValueError("D13 signed count differs from this non-authorizing preflight")
    return record_signed_d13_wire_evidence_v1(db, policy=bundle.d13_wire_policy, envelope=envelope)
