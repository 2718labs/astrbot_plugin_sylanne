"""Two fresh installed Roots, actual foreign originals, no execution capability.

Root stages this package-external helper beside the existing SDK fixture and
pins its SHA in fixture-input.json["artifact_v3_cross_root_helper_sha256"].
Root B needs a separately installed V6/V9 production-scope Mock fixture, its
own Core identity, mTLS installation, profile and Graph. No installer is run
here. The explicit protected setup makes both existing fixture sockets and
actual profile/Graph paths visible to the Root controller. No key or client
credential is sent to another Host.

SYLANNE_ARTIFACT_V3_CROSS_ROOT_SETUP names a Root-owned descriptor:
{"schema":"sylanne.test.artifact-v3-cross-root-setup.v1",
 "a_setup":"/protected/a.json","b_setup":"/protected/b.json",
 "b_socket":"/protected-root-b/run/fixture.sock",
 "b_profile_root":"/protected-root-b/client/profiles",
 "b_assets":"/protected-root-b/authority/assets.json",
 "b_package_root":"/protected-root-b/code",
 "helper_sha256":"<actual staged helper sha256>",
 "evidence_directory":"/protected/new-evidence-directory"}
a_setup and b_setup use the existing installed-snapshot-setup.v1 schema.
Both must be fresh, unknown_observation=false and retain their originally
approved deadlines, limits and maximum ceilings. B's observer provider config
must really differ from A's; equal objects are setup failure, never a negative.
B is held before its first D07 admit and remains unconsumed after this node.
The operator preserves that unresolved B fixture; there is no automatic reset,
release, replay, Root upgrade, provider fallback or lifetime extension.
"""
from pathlib import Path
from dataclasses import asdict, replace
from concurrent.futures import ThreadPoolExecutor
import asyncio
import hashlib
import json
import os
import socket
import sqlite3
import time

from sylanne3.authority_service.v2_contract import from_wire as permit_from_wire, to_wire as permit_to_wire
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1, ModelEgressDraftV1
from sylanne3.authority_service.v2_model_egress_wire import from_wire as model_from_wire, to_wire as model_to_wire
from sylanne3.runtime_contracts import InstallationGrantV2, canonical_digest
from sylanne3.domains.d01.production_operations_v1 import plain_v1

CASES = (
    ("signed_foreign_grant_basis", "binding_digest"),
    ("actual_foreign_lease", "budget_lease_id"),
    ("actual_foreign_reservation", "budget_reservation_pair"),
    ("actual_foreign_provider_configuration", "provider_config_digest"),
    ("actual_foreign_installation_grant", "installation_grant"),
)


class CrossRootAdmissionProbeV1:
    """Only the package-external existing Root fixture RPC constructs this probe."""

    def __init__(self, *, authority, runtime, bundle, grant, counts, cleanup):
        from sylanne3.host.authority_client import AuthorityClient
        from sylanne3.host.mtls_transport import MtlsAuthorityTransport
        if type(authority) is not AuthorityClient or type(authority._transport) is not MtlsAuthorityTransport:
            raise TypeError("actual installed paired client required")
        self.authority, self.runtime, self.bundle, self.grant = authority, runtime, bundle, grant
        self.counts, self.cleanup = counts, cleanup
        self.state, self.role, self.cases = "not_armed", None, []
        self.failure = None
        self.originals = None
        self.release = None
        self.index = 0
        self.valid_forward_count = 0
        self.last_trusted_now_utc = None

    def status(self):
        return {"state": self.state, "role": self.role, "cases": list(self.cases),
                "next_case": CASES[self.index][0] if self.role == "A" and self.index < len(CASES) else None,
                "valid_forward_count": self.valid_forward_count, "first_failure": self.failure,
                "request_deadline_utc": None if self.originals is None else self.originals[2].envelope.deadline_utc,
                "last_trusted_now_utc": self.last_trusted_now_utc}

    def arm(self, role):
        from unittest.mock import patch
        if role not in {"A", "B"} or self.state != "not_armed" or self.counts()["local"]:
            raise ValueError("unused fresh Root and explicit A or B role required")
        self.role, self.state = role, "armed"
        actual_admit = self.authority.model_admit_dispatch_once_v2

        async def observed(bundle, grant, *, intent, expected_anchor, model_request,
                           host_incarnation, _on_dispatch=None):
            if model_request.identity.phase != "d07.cognition":
                return await actual_admit(bundle, grant, intent=intent, expected_anchor=expected_anchor,
                    model_request=model_request, host_incarnation=host_incarnation, _on_dispatch=_on_dispatch)
            if self.state != "armed" or bundle is not self.bundle or grant is not self.grant:
                raise RuntimeError("cross-Root probe cannot repeat or borrow another installed client")
            self.originals = (intent, expected_anchor, model_request, host_incarnation)
            self.state = "held"
            try:
                before = self.counts()
                if (before["phases"] != ["encode", "appraisal", "tone_sample"]
                        or before["local"] != 3 or before["network"] or before["charge"]):
                    raise AssertionError("first real D07 must follow exactly three zero-charge Mock calls")
                await self.inspect()
                if role == "B":
                    # No callback and no admit RPC: the real B Core original stays prepared.
                    await asyncio.Future()
                    raise AssertionError("the witness Root has no release action")
                baseline = None
                for index, (name, field) in enumerate(CASES):
                    self.index, self.state = index, "waiting_root_validation"
                    self.release = asyncio.get_running_loop().create_future()
                    packet = await self.release
                    self.state = "checking"
                    foreign = model_from_wire(packet["witness"]["intent"], ModelEgressIntentV1)
                    foreign_grant = InstallationGrantV2(**packet["witness"]["installation_grant"])
                    identity = canonical_digest({key: packet["witness"][key] for key in
                        ("intent", "permit", "installation_grant", "workflow")})
                    if baseline is None:
                        baseline = identity
                    if identity != baseline:
                        raise AssertionError("Root B actual witness changed between cases")
                    current = await self.inspect()
                    now = current["trusted_now_utc"]
                    for label, proof in (("A", packet["a_snapshot"]), ("B", packet["b_snapshot"])):
                        if now >= proof["deadline_utc"]:
                            raise TimeoutError(label + " original expired before substitution; not a cross-Root rejection")
                    if packet["witness"]["trusted_now_utc"] >= packet["b_snapshot"]["deadline_utc"]:
                        raise TimeoutError("Root B current witness expired; not a cross-Root rejection")
                    if (foreign.authority_id == intent.authority_id
                            or foreign_grant.installation_id == grant.installation_id
                            or foreign_grant.subject == grant.subject
                            or packet["a_snapshot"]["root_grant_digest"] == packet["b_snapshot"]["root_grant_digest"]):
                        raise AssertionError("two actually independent fresh Roots required")
                    candidate = intent
                    candidate_grant = grant
                    if field == "installation_grant":
                        candidate_grant = foreign_grant
                        remote, expected = False, "authority model installation binding is invalid"
                    elif field == "budget_reservation_pair":
                        if (foreign.budget_reservation_operation_id, foreign.budget_reservation_digest) == (
                                intent.budget_reservation_operation_id, intent.budget_reservation_digest):
                            raise AssertionError("actual B reservation pair equals A")
                        candidate = replace(intent, budget_reservation_operation_id=foreign.budget_reservation_operation_id,
                            budget_reservation_digest=foreign.budget_reservation_digest)
                        remote, expected = True, "authority service unavailable"
                    else:
                        value = getattr(foreign, field)
                        if value == getattr(intent, field):
                            raise AssertionError("the actual foreign object equals Root A: " + name)
                        candidate = replace(intent, **{field: value})
                        remote, expected = True, "authority service unavailable"
                        if [key for key in asdict(intent) if asdict(intent)[key] != asdict(candidate)[key]] != [field]:
                            raise AssertionError("only the named actual foreign object may vary")
                    sent = []
                    try:
                        await actual_admit(bundle, candidate_grant, intent=candidate,
                            expected_anchor=expected_anchor, model_request=model_request,
                            host_incarnation=host_incarnation, _on_dispatch=lambda: sent.append(True))
                    except RuntimeError as error:
                        if type(error) is not RuntimeError or str(error) != expected:
                            raise AssertionError("unexpected actual rejection for " + name) from error
                    else:
                        raise AssertionError("foreign original admitted: " + name)
                    after = await self.inspect()
                    if (len(sent) != (1 if remote else 0) or self.counts() != before
                            or after["current"]["record"] != current["current"]["record"]
                            or after["current"]["permit"] != current["current"]["permit"]
                            or after["current"]["capacity"]["selected_admission_count"] != 0
                            or after["current"]["capacity"]["selected_observation_count"] != 0):
                        raise AssertionError("negative consumed an original, provider call or fee: " + name)
                    if after["trusted_now_utc"] >= min(packet["a_snapshot"]["deadline_utc"], packet["b_snapshot"]["deadline_utc"]):
                        raise TimeoutError("an original expired during the negative; no rejection PASS")
                    self.cases.append({"name": name, "changed_field": field,
                        "layer": "live_core_original_identity" if remote else "host_before_dispatch",
                        "rejection": expected, "actual_mtls_dispatch_count": len(sent),
                        "a_original_state": "prepared", "provider_call_delta": 0, "fixture_charge_delta_microusd": 0,
                        "a_snapshot": packet["a_snapshot"], "b_snapshot": packet["b_snapshot"],
                        "foreign_object_digest": canonical_digest(
                            plain_v1(foreign_grant) if field == "installation_grant" else
                            (foreign.budget_reservation_operation_id, foreign.budget_reservation_digest)
                            if field == "budget_reservation_pair" else getattr(foreign, field)),
                        "a_current_before_digest": canonical_digest(current["current"]),
                        "a_current_after_digest": canonical_digest(after["current"])})
                # A final Root barrier rechecks B and both budgets before the only valid admit.
                self.index, self.state = len(CASES), "waiting_original_validation"
                self.release = asyncio.get_running_loop().create_future()
                packet = await self.release
                current = await self.inspect()
                if current["trusted_now_utc"] >= min(packet["a_snapshot"]["deadline_utc"], packet["b_snapshot"]["deadline_utc"]):
                    raise TimeoutError("original validation expired before valid admission")
                self.state = "forwarding_original"
                self.valid_forward_count += 1
                result = await actual_admit(bundle, grant, intent=intent, expected_anchor=expected_anchor,
                    model_request=model_request, host_incarnation=host_incarnation, _on_dispatch=_on_dispatch)
                if result[0].state != "dispatch_started" or result[0].intent != intent:
                    raise AssertionError("unchanged A original did not obtain its sole actual admission")
                self.state = "original_admitted"
                return result
            except BaseException as error:
                self.state = "first_failure"
                self.failure = {"type": type(error).__name__, "message": str(error),
                                "wall_utc": time.time(), "automatic_replay": False,
                                "request_deadline_utc": model_request.envelope.deadline_utc,
                                "remaining_seconds": model_request.envelope.deadline_utc - max(time.time(), self.last_trusted_now_utc or time.time())}
                raise
            finally:
                interception.stop()

        interception = patch.object(self.authority, "model_admit_dispatch_once_v2", new=observed)
        interception.start()
        self.cleanup.callback(interception.stop)
        return self.status()

    async def inspect(self):
        if self.originals is None:
            return {"probe": self.status(), "witness": None}
        intent, anchor, request, incarnation = self.originals
        port, clock_policy = await self.runtime._worker.call(
            lambda graph: (graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__dispatch_clock_policy))
        from sylanne3.runtime.first_ingress_v2 import trusted_upper
        clock = await asyncio.to_thread(port.read_ingress_clock, clock_policy)
        now = trusted_upper(clock)
        self.last_trusted_now_utc = now
        if now >= request.envelope.deadline_utc:
            raise TimeoutError("prepared witness expired; deadline=" + str(request.envelope.deadline_utc)
                + " trusted_now=" + str(now) + " remaining_seconds=" + str(request.envelope.deadline_utc - now))
        actual_request, handshake, policy = await self.authority._model_installation_context(self.bundle, self.grant)
        current_anchor = await self.authority._transport.v2_current_anchor(actual_request, handshake, policy.authority_namespace)
        record, permit = await self.authority.model_recover_fenced_v1(self.bundle, self.grant, intent=intent)
        fact = await self.authority.model_capacity_reconcile_v1(self.bundle, self.grant,
            expected_anchor=current_anchor, draft=ModelEgressDraftV1.from_intent(intent), close_prepared=False)
        if (record.state != "prepared" or record.intent != intent or permit.pinned_anchor != anchor
                or fact["status"] != "prepared" or fact["selected_admission_count"] != 0
                or fact["selected_observation_count"] != 0 or not fact["capacity_available"]):
            raise AssertionError("actual paired Core no longer has its untouched prepared original")
        return {"probe": self.status(), "intent": model_to_wire(intent), "permit": permit_to_wire(permit),
            "installation_grant": asdict(self.grant),
            "workflow": plain_v1(self.bundle.model_workflows.artifact_observation_cognition),
            "trusted_now_utc": now,
            "current": {"record": model_to_wire(record), "permit": permit_to_wire(permit), "capacity": fact},
            "counts": self.counts()}

    def release_case(self, *, case, witness, a_snapshot, b_snapshot):
        expected = CASES[self.index][0] if self.index < len(CASES) else "original"
        if (self.role != "A" or self.state not in {"waiting_root_validation", "waiting_original_validation"}
                or case != expected or self.release is None or self.release.done()):
            raise ValueError("exact once-only current Root controller barrier required")
        self.release.set_result({"witness": witness, "a_snapshot": a_snapshot, "b_snapshot": b_snapshot})
        return {"released": case}


def _read_protected(path):
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    return json.loads(read_installed_bytes_v1(path, limit=65536))


def _rpc(endpoint, action, **values):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(65)
        channel.connect(str(endpoint))
        channel.sendall(json.dumps({"action": action, **values}, separators=(",", ":")).encode() + b"\n")
        with channel.makefile("rb") as stream:
            raw = stream.readline(1048577)
        if len(raw) > 1048576:
            raise ValueError("fixed fixture response bound exceeded")
        answer = json.loads(raw)
    if answer["status"] != "ok":
        raise RuntimeError("actual cross-Root SDK fixture failure: " + answer["type"])
    return answer["result"]


def verify_prepared_snapshot_v1(*, snapshot, setup, profile_root, package_root, witness):
    """Root-only read-only signature/currentness proof, granting no admission."""
    from sylanne3.host import authority_profile as profile
    from sylanne3.host.model_workflows_v9 import AdminModelWorkflowsV9
    from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
    from sylanne3.runtime.budget import get_budget_lease, require_budget_family_admissible, BudgetReceipt
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.d07_execution_v1 import (
        read_prepared_d07_execution_v1, read_original_d07_request_v1,
        read_d07_original_v1, require_current_d07_content_reads_v1)
    from sylanne3.runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
    from sylanne3.runtime.artifact_phase_observation_v1 import read_artifact_phase_observation_basis_v1
    from sylanne3.runtime.artifact_phase_postconditions_v1 import readonly_current_artifact_phase_postcondition_contract_v1
    from sylanne3.authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    from sylanne3.runtime.d11_offline_originals_v1 import _utc
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("actual isolated Root controller required")
    if (witness["counts"]["local"] != 3 or witness["counts"]["phases"] != ["encode", "appraisal", "tone_sample"]
            or witness["counts"]["network"] or witness["counts"]["charge"]):
        raise AssertionError("held Root must retain its authentic three-call zero-fee baseline")
    bundle = profile._load_installation_bundle_from_root(setup["profile_id"], Path(profile_root), "Linux")
    policy = bundle.installation_policy
    manifest = hashlib.sha256((Path(package_root) / "release-manifest.json").read_bytes()).hexdigest()
    intent = model_from_wire(witness["intent"], ModelEgressIntentV1)
    permit = permit_from_wire(witness["permit"])
    grant = InstallationGrantV2(**witness["installation_grant"])
    if (type(bundle.model_workflows) is not AdminModelWorkflowsV9
            or bundle.artifact_phase_counter.source_scope != "production"
            or manifest != policy.manifest_digest
            or (policy.installation_id, manifest, canonical_digest(policy.root_grant)) !=
               (setup["installation_id"], setup["manifest_digest"], setup["root_grant_digest"])
            or policy.root_grant.valid_until_utc != setup["original_deadline_utc"]
            or dict(policy.root_lease.limits) != setup["approved_root_limits"]
            or dict(policy.root_grant.max_ceiling) != setup["approved_root_max_ceiling"]
            or (grant.authority_id, grant.installation_id, grant.manifest_digest, grant.administrator_holder) !=
               (policy.expected_authority_id, policy.installation_id, manifest, policy.administrator_holder)
            or not grant.subject.startswith("mtls:sha256:")
            or (permit.subject, intent.subject, intent.namespace) !=
               (grant.subject, grant.subject, policy.authority_namespace)):
        raise AssertionError("actual independent V6/V9 installation pins differ")
    issuer = D11BudgetJobIssuer(D02ResourceIssuer(bundle.d02_signing_key), bundle.d11_signing_key)
    now = max(time.time(), witness["trusted_now_utc"])
    from rewrite.tests.alpha1.integration.artifact_forensic_graph_projection_v3 import forensic_artifact_snapshot_connection_v3
    with forensic_artifact_snapshot_connection_v3(snapshot=snapshot, bundle=bundle) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        prepared = read_prepared_d07_execution_v1(db, issuer, policy.namespace, intent.job_id)
        if type(prepared) is not D07ArtifactObservationPreparedV3 or prepared.digest != intent.binding_digest:
            raise AssertionError("actual signed Artifact prepared original differs from Core")
        require_current_d07_content_reads_v1(db, prepared, issuer=issuer)
        call = read_original_d07_request_v1(db, issuer, prepared)
        sealed = read_d07_original_v1(db, issuer, policy.namespace, "call", prepared.job_id)
        if (sealed is None or sealed[0] != model_to_wire(intent) or call.digest != intent.request_digest
                or (call.call_id, call.identity.operation_id, call.envelope.authority.actor) !=
                   (intent.call_id, intent.operation_id, intent.subject)):
            raise AssertionError("signed actual request/call identity differs")
        workflow = bundle.model_workflows.artifact_observation_cognition
        if (plain_v1(workflow) != witness["workflow"]
                or (workflow.provider_id, workflow.model_id, workflow.provider_config_digest) !=
                   (intent.provider_id, intent.model_id, intent.provider_config_digest)):
            raise AssertionError("wrong configuration witness is not B's actual installed workflow")
        basis = read_artifact_phase_observation_basis_v1(db, namespace=policy.namespace,
            original_ref=prepared.observation_basis_ref, issuer=issuer)
        if basis is None or basis.digest != prepared.observation_basis_digest:
            raise AssertionError("signed Source/Owner/Root basis is absent")
        contract = readonly_current_artifact_phase_postcondition_contract_v1(db, namespace=policy.namespace,
            selector=basis.request.selector, issuer=issuer, now_utc=now,
            owner_guard=basis.owner_guard, installed_bundle=bundle)
        sources = _source_family_current_sql_v1(db, namespace=policy.namespace,
            roots=tuple(head.key.token for head, _ in basis.source_heads),
            purpose=prepared.purpose, audiences=prepared.audience)
        for head, digest in basis.source_heads:
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                (*policy.namespace.as_tuple, head.key.token)).fetchone()
            if row is None or (row[0], canonical_digest(json.loads(row[1])), row[2]) != (head.revision, digest, 1):
                raise AssertionError("actual task/content Source no longer current")
        lease = get_budget_lease(db, intent.budget_lease_id)
        require_budget_family_admissible(db, lease.lease_id)
        root_grant = issuer.current_budget_grant(db, lease.lease_id)
        job = get_job(db, intent.job_id)
        quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
        reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease.lease_id, intent.budget_reservation_operation_id)).fetchone()
        if (root_grant != policy.root_grant or canonical_digest(root_grant) != basis.parent_grant_digest
                or lease.lease_id != policy.root_lease.lease_id or lease.state != "active"
                or (lease.bot_id, lease.persona_id) != policy.namespace.as_tuple
                or lease.used.get("model_microusd", 0) != 0
                or dict(lease.limits) != setup["approved_root_limits"]
                or (job.phase, job.lease_holder, job.fence, job.budget_ref) !=
                   ("running", intent.subject, intent.worker_fence, lease.lease_id)
                or quote.parent_budget_lease_ref != lease.lease_id
                or canonical_digest(quote) != prepared.quote_digest
                or quote.operation_id != intent.budget_reservation_operation_id
                or quote.operation_id != prepared.operation_id
                or reservation is None
                or reservation[0] != intent.budget_reservation_digest
                or reservation[0] != prepared.reservation_digest
                or json.loads(reservation[1]) != dict(quote.ceiling)
                or reservation[2:] != ("reserved", None)):
            raise AssertionError("actual signed grant/lease/quote/reservation/worker proof differs")
        rows = db.execute("SELECT phase,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=?", (*policy.namespace.as_tuple, quote.operation_id)).fetchall()
        if len(rows) != 1 or rows[0][0] != "reserve":
            raise AssertionError("prepared witness has no unique actual reserve and no settle")
        receipt = BudgetReceipt(**json.loads(rows[0][1]))
        if (receipt.status, receipt.operation_id, receipt.digest, receipt.lease_id) != (
                "reserved", quote.operation_id, reservation[0], lease.lease_id):
            raise AssertionError("actual D11 reserve receipt differs")
        deadline = min(setup["original_deadline_utc"], basis.original_deadline_utc,
            contract.original_deadline_utc, root_grant.valid_until_utc, call.envelope.deadline_utc,
            quote.deadline_utc, quote.valid_until_utc, _utc(job.deadline_utc).timestamp(),
            _utc(job.lease_expires_utc).timestamp())
        if max(time.time(), now) >= deadline:
            raise TimeoutError("original witness deadline elapsed before rejection: remaining=" + str(deadline - max(time.time(), now)))
        finance = tuple(tuple(row) for row in db.execute(
            "SELECT lease_id,operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
            "WHERE lease_id=? ORDER BY operation_id", (lease.lease_id,)))
        return {"snapshot_sha256": hashlib.sha256(Path(snapshot).read_bytes()).hexdigest(),
            "prepared_digest": prepared.digest, "root_grant_digest": canonical_digest(root_grant),
            "lease_digest": canonical_digest(plain_v1(lease)), "reservation_digest": reservation[0],
            "reserve_receipt_digest": canonical_digest(receipt), "quote_digest": canonical_digest(quote),
            "source_family_digest": canonical_digest(sources), "basis_digest": basis.digest,
            "owner_guard_digest": canonical_digest(basis.owner_guard), "contract_digest": contract.digest,
            "financial_digest": canonical_digest((plain_v1(lease), finance)),
            "installation_id": policy.installation_id, "authority_id": intent.authority_id,
            "provider_config_digest": workflow.provider_config_digest,
            "deadline_utc": deadline, "validated_utc": max(time.time(), now),
            "remaining_seconds": deadline - max(time.time(), now), "actual_model_charge_microusd": 0}



def verify_fresh_snapshot_v1(*, snapshot, setup, profile_root):
    from sylanne3.host import authority_profile as profile
    from sylanne3.host.model_workflows_v9 import AdminModelWorkflowsV9
    from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
    from sylanne3.runtime.budget import get_budget_lease, require_budget_family_admissible
    bundle = profile._load_installation_bundle_from_root(setup["profile_id"], Path(profile_root), "Linux")
    policy = bundle.installation_policy
    issuer = D11BudgetJobIssuer(D02ResourceIssuer(bundle.d02_signing_key), bundle.d11_signing_key)
    if (type(bundle.model_workflows) is not AdminModelWorkflowsV9
            or bundle.artifact_phase_counter.source_scope != "production"
            or policy.installation_id != setup["installation_id"]
            or policy.manifest_digest != setup["manifest_digest"]
            or canonical_digest(policy.root_grant) != setup["root_grant_digest"]
            or policy.root_grant.valid_until_utc != setup["original_deadline_utc"]
            or dict(policy.root_lease.limits) != setup["approved_root_limits"]
            or dict(policy.root_grant.max_ceiling) != setup["approved_root_max_ceiling"]):
        raise ValueError("baseline differs from exact actual V6/V9 protected Root pins")
    from rewrite.tests.alpha1.integration.artifact_forensic_graph_projection_v3 import forensic_artifact_snapshot_connection_v3
    with forensic_artifact_snapshot_connection_v3(snapshot=snapshot, bundle=bundle) as db:
        db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
        lease = get_budget_lease(db, policy.root_lease.lease_id)
        grant = issuer.current_budget_grant(db, lease.lease_id)
        require_budget_family_admissible(db, lease.lease_id)
        if (grant != policy.root_grant or lease.state != "active"
                or dict(lease.limits) != setup["approved_root_limits"]
                or lease.used.get("model_microusd", 0) != 0
                or time.time() >= setup["original_deadline_utc"]
                or db.execute("SELECT 1 FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
                    "AND work_kind='d11.foreground_cycle.v1' LIMIT 1", policy.namespace.as_tuple).fetchone() is not None):
            raise ValueError("baseline is not the signed fresh pre-episode Root")

def run_cross_root_node_v1():
    """Permanent node; missing explicit two-Root setup is a visible skip."""
    import pytest
    location = os.environ.get("SYLANNE_ARTIFACT_V3_CROSS_ROOT_SETUP")
    if location is None:
        pytest.skip("requires two explicitly prepared fresh V6/V9 installed Roots and protected cross-Root setup")
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("isolated Linux Root controller required")
    from rewrite.tests.alpha1.integration.beta1_fixture_evidence_read_v3 import (
        backup_artifact_v3_fixture_graph_v1, verify_artifact_v3_fixture_snapshot_v1)
    from rewrite.host_tests.alpha1.artifact_v3_admission_diagnostics_v1 import (
        capture_core_diagnostic_cursor_v1, require_original_intent_rejections_v1)
    setup = _read_protected(location)
    fields = {"schema", "a_setup", "b_setup", "b_socket", "b_profile_root", "b_assets",
              "b_package_root", "helper_sha256", "evidence_directory"}
    if set(setup) != fields or setup["schema"] != "sylanne.test.artifact-v3-cross-root-setup.v1":
        raise ValueError("exact protected two-Root setup required")
    a, b = _read_protected(setup["a_setup"]), _read_protected(setup["b_setup"])
    installed_fields = {"schema", "profile_id", "installation_id", "manifest_digest", "root_grant_digest",
        "original_deadline_utc", "approved_root_limits", "approved_root_max_ceiling", "graph_path",
        "evidence_directory", "message_id", "task_text", "unknown_observation"}
    for installed_setup in (a, b):
        if set(installed_setup) != installed_fields or installed_setup["schema"] != "sylanne.test.artifact-v3-installed-snapshot-setup.v1":
            raise ValueError("exact original fresh V6/V9 installed setup descriptor required")
    a_endpoint, b_endpoint = "/run/sylanne-b04-host/fixture.sock", setup["b_socket"]
    directory = Path(setup["evidence_directory"])
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    stage, barriers = "fresh_baselines", []
    last_status = {"A": None, "B": None}
    executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="artifact_cross_root_ingress")
    try:
        if (a["unknown_observation"] or b["unknown_observation"]
                or a["installation_id"] == b["installation_id"]
                or Path(a["graph_path"]).resolve() == Path(b["graph_path"]).resolve()
                or Path(a_endpoint).resolve() == Path(b_endpoint).resolve()
                or min(a["original_deadline_utc"], b["original_deadline_utc"]) <= time.time()):
            raise ValueError("actual distinct fresh Roots with original valid deadlines required")
        if Path(b["graph_path"]) != Path(_read_protected(setup["b_assets"])["graph_db"]):
            raise ValueError("B snapshot locator is not B's protected actual Authority Graph")
        if Path(a["graph_path"]) != Path(_read_protected("/etc/sylanne/authority/assets.json")["graph_db"]):
            raise ValueError("A snapshot locator is not A's protected actual Authority Graph")
        helper_path = Path("/opt/sylanne-b04-fixture/artifact_v3_cross_root_witness_v1.py")
        if hashlib.sha256(helper_path.read_bytes()).hexdigest() != setup["helper_sha256"]:
            raise ValueError("actual Root-staged Host helper differs")
        diagnostic_log = os.environ.get("SYLANNE_ARTIFACT_V3_AUTHORITY_DIAGNOSTIC_LOG")
        if not diagnostic_log:
            raise ValueError("actual A Core diagnostic log required; opaque RPC errors alone cannot qualify")
        cursor = capture_core_diagnostic_cursor_v1(diagnostic_log)
        before = {}
        for label, endpoint, protected in (("A", a_endpoint, a), ("B", b_endpoint, b)):
            health = _rpc(endpoint, "artifact_v3_checkpoint")
            if (not health["runtime_started"] or not health["worker_started"] or health["provider_network_requests"]
                    or health["local_model_requests"] or health["model_fixture_calls"]
                    or health["manifest_sha256"] != protected["manifest_digest"]
                    or not health["fixture_checkpoint"]["event_queue_empty"]
                    or health["fixture_checkpoint"]["pending_sdk_tasks"]
                    or health["fixture_checkpoint"]["worker_transaction_open"]):
                raise ValueError(label + " is not a clean fresh installed SDK Root")
            before[label] = health
            snapshot = directory / (label.lower() + "-baseline.sqlite3")
            backup_artifact_v3_fixture_graph_v1(graph_path=protected["graph_path"], target=snapshot)
            verify_fresh_snapshot_v1(snapshot=snapshot, setup=protected,
                profile_root="/etc/sylanne/client/profiles" if label == "A" else setup["b_profile_root"])
            _rpc(endpoint, "artifact_v3_cross_root_arm", role=label, helper_sha256=setup["helper_sha256"])
        if before["A"]["process_original"] == before["B"]["process_original"]:
            raise ValueError("Root B is the same Host process")
        stage = "two_actual_sdk_ingresses"
        ingress = {label: executor.submit(_rpc, endpoint, "ordinary_ingress",
            message_id=protected["message_id"], text=protected["task_text"])
            for label, endpoint, protected in (("A", a_endpoint, a), ("B", b_endpoint, b))}
        expires = min(a["original_deadline_utc"], b["original_deadline_utc"])
        released = set()
        original_a_finance = original_b_finance = None
        stage = "actual_objects_and_current_root_barriers"
        while time.time() < expires:
            for label, future in ingress.items():
                if future.done():
                    result = future.result()
                    if not all(result.get(k) for k in ("handler_entered", "handler_returned", "pipeline_entered", "pipeline_returned")):
                        raise AssertionError(label + " did not traverse the actual SDK ingress pipeline")
            astatus = _rpc(a_endpoint, "artifact_v3_cross_root_status")
            bstatus = _rpc(b_endpoint, "artifact_v3_cross_root_status")
            last_status = {"A": astatus, "B": bstatus}
            if bstatus["first_failure"] is not None:
                raise AssertionError("B preserved first failure: " + json.dumps(bstatus["first_failure"]))
            if astatus["first_failure"] is not None:
                raise AssertionError("A preserved first failure: " + json.dumps(astatus["first_failure"]))
            if astatus["state"] == "original_admitted":
                break
            aw = _rpc(a_endpoint, "artifact_v3_cross_root_inspect")
            bw = _rpc(b_endpoint, "artifact_v3_cross_root_inspect")
            for label, witness in (("A", aw), ("B", bw)):
                if witness["probe"]["first_failure"] is not None:
                    raise AssertionError(label + " preserved first failure: " + json.dumps(witness["probe"]["first_failure"]))
            if bw["probe"]["state"] != "held" or aw["probe"]["state"] not in {
                    "waiting_root_validation", "waiting_original_validation", "original_admitted"}:
                time.sleep(0.05)
                continue
            if aw["probe"]["state"] == "original_admitted":
                break
            case = aw["probe"]["next_case"] or "original"
            if case in released:
                time.sleep(0.05)
                continue
            proofs = {}
            for label, witness, protected, profiles, package in (
                    ("A", aw, a, "/etc/sylanne/client/profiles", "/opt/sylanne/code"),
                    ("B", bw, b, setup["b_profile_root"], setup["b_package_root"])):
                snapshot = directory / (label.lower() + "-" + str(len(released)) + ".sqlite3")
                backup_artifact_v3_fixture_graph_v1(graph_path=protected["graph_path"], target=snapshot)
                proofs[label] = verify_prepared_snapshot_v1(snapshot=snapshot, setup=protected,
                    profile_root=profiles, package_root=package, witness=witness)
            if (proofs["A"]["authority_id"] == proofs["B"]["authority_id"]
                    or proofs["A"]["root_grant_digest"] == proofs["B"]["root_grant_digest"]
                    or proofs["A"]["provider_config_digest"] == proofs["B"]["provider_config_digest"]):
                raise ValueError("B needs its own actual Core, signed Root and different valid provider configuration")
            if original_a_finance is None:
                ai, bi = model_from_wire(aw["intent"], ModelEgressIntentV1), model_from_wire(bw["intent"], ModelEgressIntentV1)
                # All foreign objects must differ before the first negative.
                if any(getattr(ai, field) == getattr(bi, field) for field in (
                        "binding_digest", "budget_lease_id", "budget_reservation_operation_id",
                        "budget_reservation_digest", "provider_config_digest")):
                    raise ValueError("actual B object equals A; prepare a distinct valid B fixture before any negative")
                original_a_finance, original_b_finance = proofs["A"]["financial_digest"], proofs["B"]["financial_digest"]
            if (proofs["A"]["financial_digest"], proofs["B"]["financial_digest"]) != (original_a_finance, original_b_finance):
                raise AssertionError("a prior negative changed A or B actual budget/reservation")
            # Fresh paired B proof after both snapshot reads, before releasing A.
            latest_b = _rpc(b_endpoint, "artifact_v3_cross_root_inspect")
            if canonical_digest({key: latest_b[key] for key in ("intent", "permit", "installation_grant", "workflow")}) != canonical_digest(
                    {key: bw[key] for key in ("intent", "permit", "installation_grant", "workflow")}):
                raise AssertionError("Root B witness changed during the Root read-only signature check")
            if max(time.time(), latest_b["trusted_now_utc"]) >= min(proofs["A"]["deadline_utc"], proofs["B"]["deadline_utc"]):
                raise TimeoutError("witness expired during read-only verification; not a cross-grant PASS")
            barriers.append({"case": case, "a": proofs["A"], "b": proofs["B"]})
            _rpc(a_endpoint, "artifact_v3_cross_root_release", case=case, witness=latest_b,
                a_snapshot=proofs["A"], b_snapshot=proofs["B"])
            released.add(case)
        else:
            raise TimeoutError("original A/B deadline elapsed without the sole valid A admission")
        stage = "actual_six_calls_and_delivered_receipt"
        final_serial, final_marker = 0, None
        # After valid admission inspect no longer asserts prepared; use health.
        while time.time() < expires:
            health = _rpc(a_endpoint, "artifact_v3_checkpoint")
            probe = _rpc(a_endpoint, "artifact_v3_cross_root_status")
            if probe["first_failure"] is not None or health["provider_network_requests"] or health["model_fixture_first_failure"]:
                raise AssertionError("actual first failure or provider network request")
            checkpoint = health["fixture_checkpoint"]
            if checkpoint["worker_transaction_open"] or not checkpoint["event_queue_empty"] or checkpoint["pending_sdk_tasks"]:
                time.sleep(0.05)
                continue
            if health["local_model_requests"] != 6:
                time.sleep(0.05)
                continue
            with sqlite3.connect(Path(a["graph_path"]).as_uri() + "?mode=ro", uri=True) as db:
                db.execute("PRAGMA query_only=ON")
                marker = db.execute("SELECT COALESCE(MAX(commit_seq),0) FROM graph_bundle_operations").fetchone()[0]
            if marker == final_marker:
                time.sleep(0.05)
                continue
            final_marker, final_serial = marker, final_serial + 1
            final = directory / ("a-delivered-" + str(final_serial) + ".sqlite3")
            backup_artifact_v3_fixture_graph_v1(graph_path=a["graph_path"], target=final)
            result = verify_artifact_v3_fixture_snapshot_v1(snapshot=final, setup=a)
            if result is None:
                time.sleep(0.05)
                continue
            if ([row["name"] for row in probe["cases"]] != [name for name, _ in CASES]
                    or probe["valid_forward_count"] != 1 or probe["state"] != "original_admitted"
                    or len(health["model_fixture_calls"]) != 6 or health["local_model_requests"] != 6
                    or sum(row["fixture_charge_microusd"] for row in health["model_fixture_calls"]) != 0):
                raise AssertionError("actual foreign negatives or sole valid A six-call result differ")
            core = require_original_intent_rejections_v1(diagnostic_log, cursor, count=4)
            bw = _rpc(b_endpoint, "artifact_v3_cross_root_inspect")
            bfinal = directory / "b-still-prepared.sqlite3"
            backup_artifact_v3_fixture_graph_v1(graph_path=b["graph_path"], target=bfinal)
            bp = verify_prepared_snapshot_v1(snapshot=bfinal, setup=b, profile_root=setup["b_profile_root"],
                package_root=setup["b_package_root"], witness=bw)
            if bp["financial_digest"] != original_b_finance or bw["counts"]["local"] != 3 or bw["counts"]["network"] or bw["counts"]["charge"]:
                raise AssertionError("B witness was consumed or charged")
            output = {"schema": "sylanne.test.artifact-v3-two-fresh-roots-result.v1", "status": "PASS",
                "scope": "actual valid foreign originals rejected at the recorded Host/Core gate; not a deep grant authorization claim",
                "barriers": barriers, "negative_cases": probe["cases"], "core_diagnostics": core,
                "a_originals": result, "b_final_prepared": bp, "valid_a_admissions": 1,
                "a_model_calls": 6, "b_model_calls": 3, "negative_provider_calls": 0,
                "negative_new_fee_microusd": 0, "b_remains_unresolved": True, "automatic_replay": False}
            with (directory / "result.json").open("x", encoding="utf-8") as stream:
                json.dump(output, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
            return output
        raise TimeoutError("actual delivered receipt not qualified before original A/B deadlines")
    except BaseException as error:
        failure = {"schema": "sylanne.test.artifact-v3-two-roots-first-failure.v1", "stage": stage,
            "type": type(error).__name__, "message": str(error), "wall_utc": time.time(),
            "a_original_deadline_utc": a["original_deadline_utc"], "b_original_deadline_utc": b["original_deadline_utc"],
            "a_remaining_seconds": a["original_deadline_utc"] - time.time(),
            "b_remaining_seconds": b["original_deadline_utc"] - time.time(), "barriers": barriers,
            "automatic_replay": False, "last_host_status": last_status}
        with (directory / "first-failure.json").open("x", encoding="utf-8") as stream:
            json.dump(failure, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
        raise
    finally:
        executor.shutdown(wait=False, cancel_futures=False)
