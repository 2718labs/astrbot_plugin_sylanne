"""The installed host may attest an adapter ACK, never recipient delivery."""

from dataclasses import replace
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.installed_platform_observation import (
    HostOneBotObservationInstallationV2,
    InstalledHostOneBotObservationVerifierV2,
)
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.reverse_handoff import ReverseGraphClaimClient
from sylanne3.authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, ExecutionBindingV1, PlatformObservationV2,
    canonical_digest,
)
from sylanne3.authority_service.v2_execution_bridge import handoff_start_digest_v2
from sylanne3.runtime_journal import RecoveryConstraintFootprint
from sylanne3.runtime_contracts import NamespaceId

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from test_execution_binding_v2_claim import _binding_v2, _digest, _service


PEER = "a" * 64
ACCOUNT = json.dumps(["adapter-a", "aiocqhttp", "12345"], separators=(",", ":"))


def _case(tmp_path):
    def graph_claim(context, binding, _claimed, _owner, _snapshot):
        return DispatchGraphClaimReceiptV1(
            canonical_digest(context), binding.graph_namespace,
            binding.graph_incarnation, "graph-version-b", 4, 2, 0,
            "graph-claim-a", _digest("8"), "graph-issuer-a")

    core, fences, journal, bridge = _service(
        tmp_path, with_owner=True, final_authorizer=graph_claim,
        final_issuer="graph-issuer-a")
    subject = "mtls:sha256:" + PEER
    namespace = core._db.execute(
        "SELECT namespace FROM authority_namespaces LIMIT 1").fetchone()[0]
    footprint = RecoveryConstraintFootprint(
        namespace=namespace, activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",))
    with core._tx() as db:
        anchor = core._anchor(db, namespace, core._row(db, namespace))
    footprint_digest = "sha256:" + hashlib.sha256(
        footprint._json().encode()).hexdigest()
    permit = fences.begin_fence(
        subject=subject, holder="holder-a", operation="dispatch",
        current_anchor=anchor, operation_id="operation-a", effect_id="effect-a",
        command_digest=_digest("a"), footprint_digest=footprint_digest)
    prepared, _ = bridge.execution_prepare(
        credential="ok", subject=subject, permit=permit,
        mutation_id="mutation-a", footprint=footprint)
    origin = ExecutionBindingV1(
        permit=permit, namespace=namespace, activity_id="activity-a",
        effect_id="effect-a", attempt_id="attempt-a", operation_id="operation-a",
        dispatch_generation=1, activation_generation=permit.generation,
        admission_ref="admission-a", verified_check_refs=("check-a",),
        payload_digest=_digest("b"), platform_capability_ref="capability-a",
        adapter_ref="adapter-a", account_ref=ACCOUNT,
        destination_ref="destination-a", worker_fence=1,
        content_fence="content-a", cancel_epoch=0, footprint=footprint)
    binding = _binding_v2(origin)
    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject=subject, prepared_receipt=prepared,
        binding=binding)
    start = bridge.begin_handoff_v2(
        credential="ok", subject=subject, claimed_receipt=claimed,
        handoff_id="handoff-a")
    observation = PlatformObservationV2(
        binding, start.handoff_id, handoff_start_digest_v2(start),
        origin.adapter_ref, origin.account_ref, origin.destination_ref,
        "observation:" + hashlib.sha256(start.handoff_id.encode()).hexdigest(),
        None, "17", "astrbot:onebot:call_action", "accepted",
        "2026-09-27T01:00:00Z", "clock-policy-a")
    verifier = InstalledHostOneBotObservationVerifierV2(
        namespace=permit.namespace, peer_certificate_sha256=PEER,
        adapter_ref=origin.adapter_ref, account_ref=ACCOUNT,
        clock_source_ref="clock-policy-a")
    return core, journal, bridge, verifier, claimed, observation


def test_accepts_only_installed_hosts_adapter_ack_or_unknown(tmp_path):
    core, journal, bridge, verifier, claimed, report = _case(tmp_path)
    try:
        assert verifier(verifier.namespace, claimed, report) is report
        bridge._observation_verifier = verifier
        observed, _ = bridge.execution_observe_v2(
            credential="ok", subject=claimed.pending.permit.subject,
            claimed_receipt=claimed, observation=report)
        assert observed.pending.platform_observation == report
        unknown = replace(report, outcome="unknown", platform_message_id=None)
        assert verifier(verifier.namespace, claimed, unknown) is unknown
        assert verifier(verifier.namespace, claimed, replace(
            report, outcome="delivered")) is None
        assert verifier(verifier.namespace, claimed, replace(
            report, outcome="read")) is None
        assert verifier(verifier.namespace, claimed, replace(
            report, outcome="unknown")) is None
    finally:
        core.close()
        journal.close()


def test_rejects_wrong_peer_route_source_clock_and_observation_id(tmp_path):
    core, journal, _, verifier, claimed, report = _case(tmp_path)
    try:
        wrong_peer = InstalledHostOneBotObservationVerifierV2(
            namespace=verifier.namespace,
            peer_certificate_sha256="b" * 64,
            adapter_ref=verifier.adapter_ref,
            account_ref=ACCOUNT,
            clock_source_ref=verifier.clock_source_ref)
        assert wrong_peer(wrong_peer.namespace, claimed, report) is None
        assert verifier("another-namespace", claimed, report) is None
        assert verifier(verifier.namespace, claimed, replace(
            report, evidence_source_ref="payload:says-accepted")) is None
        assert verifier(verifier.namespace, claimed, replace(
            report, time_source_ref="another-clock")) is None
        assert verifier(verifier.namespace, claimed, replace(
            report, observation_id="observation:forged")) is None
        # The send was admitted before the deadline. A late adapter ACK is
        # still an external fact and must remain recordable.
        late_ack = replace(report, observed_at_utc="2029-01-01T00:00:01Z")
        assert verifier(verifier.namespace, claimed, late_ack) is late_ack
        wrong_origin = replace(report.binding.origin, account_ref=json.dumps(
            ["adapter-a", "aiocqhttp", "99999"], separators=(",", ":")))
        wrong_route = replace(report, binding=replace(report.binding,
                                                       origin=wrong_origin),
                              account_ref=wrong_origin.account_ref)
        assert verifier(verifier.namespace, claimed, wrong_route) is None
    finally:
        core.close()
        journal.close()


def test_late_ack_is_durably_recorded_after_send_deadline(tmp_path):
    core, journal, bridge, verifier, claimed, report = _case(tmp_path)
    try:
        late_ack = replace(report, observed_at_utc="2029-01-01T00:00:01Z")
        bridge._observation_verifier = verifier
        observed, _ = bridge.execution_observe_v2(
            credential="ok", subject=claimed.pending.permit.subject,
            claimed_receipt=claimed, observation=late_ack)
        assert observed.pending.platform_observation == late_ack
    finally:
        core.close()
        journal.close()


def test_rejects_unpinned_or_non_onebot_installation():
    with pytest.raises(ValueError, match="identity"):
        InstalledHostOneBotObservationVerifierV2(
            namespace="ns", peer_certificate_sha256="unbound",
            adapter_ref="adapter", account_ref=ACCOUNT,
            clock_source_ref="clock")
    with pytest.raises(ValueError, match="account"):
        InstalledHostOneBotObservationVerifierV2(
            namespace="ns", peer_certificate_sha256=PEER,
            adapter_ref="adapter", account_ref='["adapter","other","12345"]',
            clock_source_ref="clock")


def test_local_composition_requires_matching_installed_peer_and_clock(tmp_path):
    service, core, _, _, _, execution, _ = installed(tmp_path)
    graph_path = tmp_path / "graph.db"
    sqlite3.connect(graph_path).close()
    reverse = object.__new__(ReverseGraphClaimClient)
    reverse.profile = SimpleNamespace(
        namespace="ns-a", profile_id="profile", installation_id="installation")
    config = HostOneBotObservationInstallationV2(
        PEER, "profile", "adapter-a", ACCOUNT, "clock-policy-a")

    def compose(*, source_id="clock-policy-a", observation=config):
        return compose_local_owner_authority(
            core=core, v2_fences={"ns-a": service}, graph_db_path=graph_path,
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=lambda *_: False,
            claimant_verifier=lambda *_: False,
            administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2={(PEER, "profile"): AdministratorInstallationV2(
                "installation", "holder-a", "policy", "capabilities-v2",
                "b" * 64, source_id, 1.0)},
            namespace_bindings_v2={
                (PEER, "profile", NamespaceId("bot", "persona")): "ns-a"},
            v2_final_handoff_reverse={"ns-a": reverse},
            v2_final_handoff_issuers={"ns-a": "graph-issuer"},
            host_onebot_observations_v2={"ns-a": observation},
            create_owner_schema=True)

    try:
        server = compose()
        assert type(server._v2_execution["ns-a"]._observation_verifier) is (
            InstalledHostOneBotObservationVerifierV2)
        with pytest.raises(AuthorityUnavailable,
                           match="OneBot observation installation differs"):
            compose(source_id="another-clock")
        with pytest.raises(AuthorityUnavailable,
                           match="OneBot observation installation differs"):
            compose(observation=HostOneBotObservationInstallationV2(
                "c" * 64, "profile", "adapter-a", ACCOUNT, "clock-policy-a"))
    finally:
        core.close()
        execution.close()
