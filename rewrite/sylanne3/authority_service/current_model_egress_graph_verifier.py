"""Read-only first-ingress graph facts for a future model-egress authority.

Even a complete graph binding is not an Authority model fence or an executable
provider admission. The callable remains HOLD until those independent gates.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable

from .v2_contract import FencePermitV2, from_wire
from .v2_model_egress_contract import ModelEgressIntentV1
from ..contracts import canonical_json
from ..graph_types import GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    build_first_ingress_encoding_payload,
)
from ..runtime.budget import get_budget_lease
from ..runtime.d11_types import RuntimeOutboxValue, job_graph_write, runtime_job_key, runtime_outbox_key
from ..runtime.encoding_call_binding import load_binding
from ..runtime.first_ingress_v2 import ingress_ids
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime.jobs import get_job
from ..runtime_contracts import (
    NamespaceId, SnapshotRequirementsV2, SourceQualification, VersionGuard,
    canonical_serialize,
)


def _canonical(value: str):
    result = json.loads(value)
    if canonical_json(result) != value:
        raise ValueError("noncanonical persisted JSON")
    return result


class PinnedCurrentModelEgressGraphVerifier:
    """Check original business facts in one pinned, read-only SQLite snapshot.

    ``graph_facts_current`` verifies ingress, acquire, source/access, and the
    original budget. ``complete_graph_current`` additionally checks the one
    durable model request in the same read snapshot. Neither method validates
    the new Authority fence or the administrator's live provider configuration.
    These are admission checks, not a result-read proof: they receive no
    consumer Owner principal/session or read purpose/audience, do not compare
    the current Owner graph grant, and require the original job to be running,
    its outbox pending and its budget reserved. They cannot authorize release
    of a completed provider body after a terminal receipt.
    """

    def __init__(self, graph_db_path: str | Path, *,
                 d11_issuer: D11BudgetJobIssuer,
                 trusted_now_utc: Callable[[], float]):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("graph database path must be administrator-pinned and absolute")
        if type(d11_issuer) is not D11BudgetJobIssuer or not callable(trusted_now_utc):
            raise TypeError("pinned D11 issuer and trusted clock are required")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")
        self._issuer = d11_issuer
        self._clock = trusted_now_utc

    def __call__(self, intent: ModelEgressIntentV1) -> bool:
        # A graph row alone cannot authenticate the live Authority model fence
        # or the administrator-bound provider and executable token ceiling.
        return False

    def graph_facts_current(self, intent: ModelEgressIntentV1) -> bool:
        return self._current(intent, include_binding=False)

    def complete_graph_current(self, intent: ModelEgressIntentV1) -> bool:
        return self._current(intent, include_binding=True)

    def _current(self, intent: ModelEgressIntentV1, *, include_binding: bool) -> bool:
        if type(intent) is not ModelEgressIntentV1:
            return False
        try:
            now = self._clock()
            if type(now) not in (float, int) or not math.isfinite(now):
                return False
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return (self._check(db, intent, float(now))
                            and (not include_binding or self._check_binding(
                                db, intent, float(now))))
                finally:
                    db.execute("ROLLBACK")
        except Exception:
            return False

    @staticmethod
    def _check_binding(db: sqlite3.Connection, intent: ModelEgressIntentV1,
                       now: float) -> bool:
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        binding = load_binding(db, namespace, intent.job_id)
        if binding is None:
            return False
        source_id = intent.source_refs[0]
        source_token = source_key(*namespace.as_tuple, source_id).token
        source_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (source_token,),
        ).fetchone()
        if source_row is None or source_row[2] != 1:
            return False
        source = SourceRecord.from_dict(_canonical(source_row[1]))
        access_key_value = access_key(*namespace.as_tuple, source_id)
        access_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access_key_value.token,),
        ).fetchone()
        if (access_row is None or access_row[2] != 1
                or access_row[0] != binding.access_revision):
            return False
        access = _canonical(access_row[1])
        validate_access(access)
        if access["status"] != "active" or access["source_id"] != source_id:
            return False
        payload, template_digest = build_first_ingress_encoding_payload(source)
        frozen = binding.request
        envelope = frozen["envelope"]
        request_authority = envelope["authority"]
        purpose = request_authority["purpose"]
        audience = request_authority["audience"]
        request_deadline = envelope["deadline_utc"]
        if (type(purpose) is not str or type(audience) is not list
                or not audience or any(type(item) is not str for item in audience)
                or type(request_deadline) not in (int, float)
                or not now < request_deadline
                <= min(datetime.fromisoformat(job.deadline_utc.replace(
                    "Z", "+00:00")).timestamp(),
                       datetime.fromisoformat(job.lease_expires_utc.replace(
                           "Z", "+00:00")).timestamp())
                or purpose not in source.purposes
                or purpose not in access["purposes"]
                or not set(audience).issubset(source.audiences)
                or not set(audience).issubset(access["audiences"])):
            return False
        # Only the identically named reservation dimension is a proof for
        # max_completion_tokens. cpu_ms or currency cannot be converted here.
        output_token_limit = dict(intent.budget_ceiling).get("output_tokens")
        if (type(output_token_limit) is not int
                or output_token_limit < intent.max_output_tokens):
            return False
        versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND kind IN ('scheme','operator','policy') AND ref='current'",
            namespace.as_tuple,
        ).fetchall()
        if len(versions) != 3 or len({kind for kind, _ in versions}) != 3:
            return False
        current = dict(versions)
        provisions = db.execute(
            "SELECT receipt_json FROM graph_namespace_provisioning_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchall()
        if len(provisions) != 1:
            return False
        catalogue = _canonical(provisions[0][0]).get("catalogue_hash")
        expected_guard = VersionGuard(
            (GraphVersion(source_key(*namespace.as_tuple, source_id), source_row[0]),
             GraphVersion(access_key_value, access_row[0])), (),
            intent.access_epoch, intent.delete_epoch, catalogue,
            current["scheme"], current["operator"], current["policy"],
            (), (), (),
        )
        original = db.execute(
            "SELECT source_qualification_json FROM runtime_ingress_issuance "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (job.operation_id,),
        ).fetchone()
        if original is None or original[0] is None:
            return False
        qualification_data = _canonical(original[0])
        qualification_data["source_refs"] = tuple(qualification_data["source_refs"])
        qualification = SourceQualification(**qualification_data)
        if (canonical_serialize(asdict(qualification)) != original[0]
                or qualification.source_refs != (source_token,)
                or envelope["version_guard"]
                != json.loads(canonical_serialize(expected_guard))
                or envelope["source_qualification"]
                != json.loads(canonical_serialize(qualification))):
            return False
        return (
            binding.call_id == intent.call_id
            and binding.model_request_digest == intent.request_digest
            and binding.source_id == source_id
            and binding.source_revision == intent.source_revisions[0][1] == source_row[0]
            and binding.access_revision == intent.access_revisions[0][1]
            and binding.budget_lease_id == intent.budget_lease_id
            and binding.budget_reservation_operation_id == intent.budget_reservation_operation_id
            and frozen["provider_id"] == intent.provider_id
            and frozen["model_id"] == intent.model_id
            and frozen["provider_config_digest"] == intent.provider_config_digest
            and frozen["max_output_tokens"] == intent.max_output_tokens
            and frozen["prompt_template_version"] == FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
            and frozen["prompt_template_digest"] == template_digest
            and frozen["payload"] == payload
            and envelope["identity"]["operation_id"] == intent.operation_id
            and envelope["identity"]["activity_id"] == job.activity_id
            and envelope["schema"] == "sylanne.runtime.v1"
            and envelope["authority"]["actor"] == intent.subject
            and envelope["authority"]["issuer_domain"] == "d11"
            and envelope["authority"]["worker_fence"] == intent.worker_fence
            and envelope["authority"]["activation_generation"]
            == intent.authority_activation_generation
            and envelope["authority"]["namespace"] == json.loads(canonical_serialize(namespace))
            and envelope["source_qualification"]["source_refs"] == [source_token]
            and envelope["input_refs"] == [source_token]
            and envelope["parent_budget_lease_ref"] == intent.budget_lease_id
        )

    def _check(self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
               now: float) -> bool:
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        access_epoch = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] != intent.graph_revision
                or epoch != (intent.graph_epoch,)
                or access_epoch != (intent.access_epoch, intent.delete_epoch)):
            return False
        requirements_data = _canonical(recovery[1])
        if (type(requirements_data) is not dict
                or requirements_data.get("namespace") != asdict(namespace)):
            return False
        requirements = SnapshotRequirementsV2(**{
            **requirements_data, "namespace": namespace})
        if (requirements.authority_id != intent.authority_id
                or requirements.authority_namespace != intent.namespace
                or requirements.activation_generation
                != intent.authority_activation_generation
                or requirements.revocation_epoch != intent.authority_revocation_epoch
                or requirements.deletion_seq != intent.authority_deletion_seq
                or requirements.execution_seq != intent.authority_execution_seq):
            return False
        if ((job.bot_id, job.persona_id) != ns or job.work_kind != "d06.encode_source"
                or job.effect_id is not None or job.phase != "running"
                or job.fence != intent.worker_fence or job.cancel_epoch != 0
                or job.lease_holder != intent.subject or job.result_ref is not None
                or job.lease_expires_utc is None
                or datetime.fromisoformat(job.lease_expires_utc.replace(
                    "Z", "+00:00")).timestamp() <= now
                or datetime.fromisoformat(job.deadline_utc.replace(
                    "Z", "+00:00")).timestamp() <= now):
            return False
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,)).fetchone()
        if (job_atom is None or job_atom[2] != 1
                or _canonical(job_atom[1]) != job_graph_write(job).value):
            return False
        receipt = db.execute(
            "SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (job.operation_id,)).fetchone()
        if receipt is None or receipt[:2] != (job.activity_id, None):
            return False
        receipt_data = _canonical(receipt[2])
        outbox_rows = db.execute(
            "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND owner_kind='activity' AND subject=? AND type_name='runtime.outbox'",
            ns + (job.activity_id,)).fetchall()
        matches = [row for row in outbox_rows if _canonical(row[2]).get("job_id") == job.job_id]
        if len(matches) != 1:
            return False
        outbox_row = matches[0]
        outbox = RuntimeOutboxValue(**_canonical(outbox_row[2]))
        expected = ingress_ids(outbox.payload_ref)
        outbox_key = runtime_outbox_key(*ns, job.activity_id, outbox.outbox_id)
        dependency = db.execute(
            "SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? "
            "AND dependency_token=?", (outbox_key.token, job_key.token)).fetchone()
        if (outbox_row[0] != outbox_key.token or outbox_row[3] != 1
                or expected[1:5] != (job.activity_id, job.operation_id,
                                     job.job_id, outbox.outbox_id)
                or outbox.job_id != job.job_id or outbox.job_ref != job_key.token
                or outbox.idempotency_key != expected[5]
                or outbox.phase != "pending" or outbox.dispatch_generation != 1
                or (outbox.bot_id, outbox.persona_id, outbox.activity_id,
                    outbox.operation_id, outbox.effect_id) != (
                    *ns, job.activity_id, job.operation_id, None)
                or dependency != (job_atom[0],)
                or outbox_key.token not in receipt_data.get("outbox_refs", ())
                or job_key.token not in receipt_data.get("ledger_refs", ())):
            return False
        source_ref = outbox.payload_ref
        if intent.source_refs != (source_ref,):
            return False
        source_key_value = source_key(*ns, source_ref)
        access_key_value = access_key(*ns, source_ref)
        source_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (source_key_value.token,)).fetchone()
        access_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access_key_value.token,)).fetchone()
        if (source_row is None or access_row is None
                or source_row[2] != 1 or access_row[2] != 1
                or intent.source_revisions != ((source_ref, source_row[0]),)
                or intent.access_revisions != ((source_ref, access_row[0]),)):
            return False
        source = SourceRecord.from_dict(_canonical(source_row[1]))
        access = _canonical(access_row[1])
        validate_access(access)
        source_dependency = db.execute(
            "SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? "
            "AND dependency_token=?", (access_key_value.token,
                                       source_key_value.token)).fetchone()
        if (source.source_id != source_ref or access["source_id"] != source_ref
                or access["status"] != "active"
                or "consolidation" not in source.purposes
                or "consolidation" not in access["purposes"]
                or not set(access["audiences"]).issubset(source.audiences)
                or source_dependency != (source_row[0],)):
            return False
        quote_ref = job.operator_versions.get("resource_quote")
        if type(quote_ref) is not str or ":" not in quote_ref:
            return False
        quote_id, version_text = quote_ref.rsplit(":", 1)
        quote = self._issuer.resource_issuer._load_quote(db, quote_id, int(version_text))
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id)).fetchone()
        ceiling = dict(intent.budget_ceiling)
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or reservation is None
                or reservation != (intent.budget_reservation_digest,
                                   canonical_json(ceiling), "reserved")
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id != job.operation_id
                or quote.ceiling != ceiling or quote.graph_job_ref != job_key.token
                or quote.outbox_refs != (outbox_key.token,)
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.deadline_utc != datetime.fromtimestamp(
                    quote.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
                or (quote.bot_id, quote.persona_id, quote.activity_id,
                    quote.operation_id, quote.work_kind,
                    quote.parent_budget_lease_ref) != (
                    *ns, job.activity_id, job.operation_id, job.work_kind, job.budget_ref)
                or (grant.bot_id, grant.persona_id, grant.lease_id) != (
                    *ns, job.budget_ref)
                or (lease.bot_id, lease.persona_id) != ns
                or job.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(key, 0)
                       for key, amount in ceiling.items())
                or any(lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        acquire = db.execute(
            "SELECT i.job_id,i.original_operation_id,i.actor,r.job_json,r.permit_json,"
            "r.post_graph_revision,r.post_graph_epoch "
            "FROM graph_job_acquire_receipts_v2 AS r "
            "JOIN graph_job_acquire_intents_v2 AS i ON "
            "i.bot=r.bot AND i.persona=r.persona "
            "AND i.acquire_operation_id=r.acquire_operation_id "
            "WHERE r.bot=? AND r.persona=? AND i.job_id=?",
            ns + (job.job_id,)).fetchall()
        if (len(acquire) != 1 or acquire[0][:3] != (
                job.job_id, job.operation_id, job.lease_holder)
                or _canonical(acquire[0][3]) != asdict(job)):
            return False
        permit = from_wire(_canonical(acquire[0][4]))
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.authority_id != intent.authority_id
                or permit.namespace != intent.namespace
                or acquire[0][5] > intent.graph_revision
                or acquire[0][6] > intent.graph_epoch):
            return False
        return True


__all__ = ["PinnedCurrentModelEgressGraphVerifier"]
