"""Pinned read-only Graph facts for Authority model-egress admission.

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
from .current_d04_baseline_graph_proof import committed_baseline_current
from ..contracts import canonical_json
from ..graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from ..graph_store import GraphStore
from ..domains.d06 import source_correction_head_key
from ..domains.d07 import attention_ticket_key
from ..domains.d07.qualified_attention_read import (
    read_qualified_focus_attention_ticket,
)
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    build_first_ingress_encoding_payload,
)
from ..runtime.budget import get_budget_lease, require_budget_family_admissible
from ..runtime.c02_bundle_codec import c02_bundle_from_wire
from ..runtime.d11_types import RuntimeOutboxValue, job_graph_write, runtime_job_key, runtime_outbox_key
from ..runtime.encoding_call_binding import (
    CommittedEncodingBaselineV1, binding_to_json, load_binding,
)
from ..runtime.first_ingress_v2 import ingress_ids
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime.jobs import get_job
from ..runtime.reply_model_job import (
    read_current_reply_model_inputs_v1, read_saved_reply_job_v1,
    reply_binding_digest_v1, reply_envelope_from_wire_v1,
    reply_request_wire_v1, source_key_from_ref,
)
from ..runtime.restore_anchor import RestoreAnchor
from ..model_broker.reply_language import (
    REPLY_TEMPLATE_DIGEST, issue_reply_request_v1,
)
from ..runtime_contracts import (
    NamespaceId, QueryEpoch, SnapshotRequirementsV2, SourceQualification,
    VersionGuard, VersionedRef,
    canonical_digest, canonical_serialize,
)


def _canonical(value: str):
    result = json.loads(value)
    if canonical_json(result) != value:
        raise ValueError("noncanonical persisted JSON")
    return result


class PinnedCurrentModelEgressGraphVerifier:
    """Check original business facts in one pinned, read-only SQLite snapshot.

    ``graph_facts_current`` verifies the original job, source/access, and
    budget. ``complete_graph_current`` additionally checks the one durable
    model request in the same read snapshot. Neither method validates
    the new Authority fence or the administrator's live provider configuration.
    These are admission checks, not a result-read proof: they receive no
    consumer Owner principal/session or read purpose/audience, do not compare
    the current Owner graph grant, and require the original job to be running,
    its outbox pending and its budget reserved. They cannot authorize release
    of a completed provider body after a terminal receipt.
    """

    def __init__(self, graph_db_path: str | Path, *,
                 d11_issuer: D11BudgetJobIssuer,
                 trusted_now_utc: Callable[[], float],
                 trusted_paired_clock: Callable[[], tuple[float, str]] | None = None,
                 natural_history_verifier=None):
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
        self._paired_clock = trusted_paired_clock
        self._natural_history = natural_history_verifier
        self._contact_policy_service = None

    def install_contact_policy_service_v1(self, service):
        from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
        if type(service) is not InstalledD10ContactPolicyServiceV1 or self._contact_policy_service is not None:
            raise ValueError("actual contact policy service must be installed exactly once")
        self._contact_policy_service = service

    def __call__(self, intent: ModelEgressIntentV1) -> bool:
        # A graph row alone cannot authenticate the live Authority model fence
        # or the administrator-bound provider and executable token ceiling.
        return False

    def graph_facts_current(self, intent: ModelEgressIntentV1) -> bool:
        return self._current(intent, include_binding=False)

    def complete_graph_current(self, intent: ModelEgressIntentV1, *,
                               source_location=None, location_observation=None) -> bool:
        return self._current(intent, include_binding=True,
                             source_location=source_location,
                             location_observation=location_observation)

    def _current(self, intent: ModelEgressIntentV1, *, include_binding: bool,
                 source_location=None, location_observation=None) -> bool:
        if type(intent) is not ModelEgressIntentV1:
            return False
        try:
            if (source_location is None) != (location_observation is None):
                return False
            if source_location is not None:
                from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
                if (not include_binding
                        or type(source_location) is not InstalledCurrentSourceLocationQualifierV1):
                    return False
            if include_binding:
                if self._paired_clock is None:
                    return False
                reading = self._paired_clock()
                if type(reading) is not tuple or len(reading) != 2:
                    return False
                now, clock_epoch = reading
                if type(clock_epoch) is not str or not clock_epoch:
                    return False
            else:
                now, clock_epoch = self._clock(), None
            if type(now) not in (float, int) or not math.isfinite(now):
                return False
            # UTC upper bound and epoch must come from one trusted sample.
            # The persisted monotonic deadline is only request identity.
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    if source_location is not None:
                        source_location.require_graph_snapshot_v1(
                            db, location_observation, graph_db_path=self._path)
                    job = get_job(db, intent.job_id)
                    if (location_observation is not None
                            and NamespaceId(job.bot_id, job.persona_id)
                                != location_observation.namespace_id):
                        return False
                    if job.work_kind == "reply":
                        return self._check_reply(
                            db, intent, float(now), clock_epoch,
                            include_binding=include_binding)
                    if job.work_kind == "context_reply":
                        return self._check_context_reply(
                            db, intent, float(now),
                            include_binding=include_binding)
                    if job.work_kind == "natural_generation":
                        return self._check_natural_stage(
                            db, intent, float(now),
                            stage="generation",
                            include_binding=include_binding)
                    if job.work_kind in {"contact_generation", "contact_review"}:
                        from .contact_model_graph_v1 import read_current_contact_model_graph_v1
                        if self._contact_policy_service is None:
                            return False
                        read_current_contact_model_graph_v1(db, intent, self._issuer, float(now),
                            allow_unsealed_prepare=not include_binding,
                            contact_policy_service=self._contact_policy_service)
                        return True
                    if job.work_kind == "natural_review":
                        return self._check_natural_stage(
                            db, intent, float(now),
                            stage="review",
                            include_binding=include_binding)
                    if job.work_kind == "d04.appraisal":
                        from .current_d04_appraisal_v3 import read_current_d04_appraisal_graph_v3
                        read_current_d04_appraisal_graph_v3(db, intent, self._issuer, float(now),
                            allow_unsealed_prepare=not include_binding)
                        return True
                    if job.work_kind in {"d07.concern", "d07.reflection", "d07.simulation"}:
                        from .d07_current_execution_v1 import read_current_d07_execution_graph_v1
                        read_current_d07_execution_graph_v1(db, intent, self._issuer, float(now),
                            allow_unsealed_prepare=not include_binding)
                        return True
                    if job.work_kind == "d13.precompress.paid.v1":
                        return self._check_d13_paid(
                            db, intent, float(now),
                            include_binding=include_binding)
                    return (self._check(db, intent, float(now))
                            and (not include_binding or self._check_binding(
                                db, intent, float(now), clock_epoch)))
                finally:
                    db.execute("ROLLBACK")
        except Exception:
            return False

    def _check_d13_paid(self, db: sqlite3.Connection,
                        intent: ModelEgressIntentV1, now: float, *,
                        include_binding: bool) -> bool:
        from .current_d13_paid_model_graph import read_current_d13_paid_model_graph
        current = read_current_d13_paid_model_graph(
            db, intent, self._issuer, now)
        binding = current.original.binding
        if (intent.operation_id != binding.original_operation_id
                or intent.acquire_operation_id != binding.original_operation_id
                or intent.binding_digest != binding.binding_digest
                or intent.call_id != binding.call_id):
            return False
        if not include_binding:
            return True
        # The immutable D13 paid original is not allowed to attest its own
        # request digest.  Admission requires W01's durable request copy.
        from ..model_broker.d13_precompression import (
            D13PrecompressionInstallationV1,
            d13_model_request_shape_valid_v1,
            freeze_d13_precompression_request_v1,
        )
        from .current_d13_paid_model_graph import _plan, _window, _canonical
        frozen_data = _canonical(current.original.frozen_json)
        frozen = freeze_d13_precompression_request_v1(
            _window(frozen_data["window"]), _plan(frozen_data["plan"]),
            D13PrecompressionInstallationV1(**frozen_data["installation"]),
        )
        request = current.request
        guard = request.envelope.version_guard
        read_versions = {item.key.token: item.revision
                         for item in guard.read_versions}
        required = {ref.ref: ref.version for ref in (
            frozen.plan.scene_ref, frozen.plan.audience_ref,
            *frozen.plan.source_dependencies)}
        if (len(read_versions) != len(guard.read_versions)
                or not all(read_versions.get(ref) == version
                           for ref, version in required.items())
                or (guard.access_epoch, guard.delete_epoch) != (
                    intent.access_epoch, intent.delete_epoch)
                or any(item.namespace != current.original.namespace
                       or item.revision > intent.graph_epoch
                       for item in guard.query_epochs)):
            return False
        for token, revision in read_versions.items():
            row = db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (token,),
            ).fetchone()
            if row != ((revision, 1) if revision else None):
                return False
        return (d13_model_request_shape_valid_v1(request, frozen)
                and request.digest == intent.request_digest
                and request.call_id == binding.call_id
                and request.identity.operation_id == binding.original_operation_id
                and request.identity.phase == "d13.precompress"
                and request.envelope.authority.issuer_domain == "d13"
                and request.envelope.authority.actor == intent.subject
                and request.envelope.authority.worker_fence == current.job.fence
                and request.envelope.authority.activation_generation ==
                    intent.authority_activation_generation
                and request.envelope.authority.namespace == current.original.namespace
                and request.envelope.authority.audience == (
                    current.window.conversation_ref,)
                and request.envelope.parent_budget_lease_ref == current.job.budget_ref
                and now < request.envelope.deadline_utc
                and request.envelope.deadline_utc <= min(
                    datetime.fromisoformat(current.job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(current.job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    binding.expires_at_utc))

    @staticmethod
    def _reply_snapshot(db: sqlite3.Connection, namespace: NamespaceId,
                        source_ref: str, graph_epoch: int,
                        now: float):
        """Independently rebuild D07's full source closure in one graph read.

        The graph's saved guard is compared only after this read. It never
        supplies the source list, ancestry, access decisions or correction
        head absence used here.
        """
        source_id = source_key_from_ref(source_ref, namespace)
        ingress = db.execute(
            "SELECT conversation_ref FROM graph_first_ingress_identity_v1 "
            "WHERE bot=? AND persona=? AND source_ref=?",
            namespace.as_tuple + (source_id,),
        ).fetchall()
        if len(ingress) != 1:
            raise ValueError("reply source has no unique original audience")
        focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                            "d07.focus.v1", namespace.persona_id)
        atoms = {}

        def load(key: AtomKey) -> GraphAtom:
            if key not in atoms:
                row = db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (key.token,),
                ).fetchone()
                atoms[key] = (GraphAtom(key, row[0], _canonical(row[1]), bool(row[2]))
                              if row else GraphAtom(key, 0, {}, False))
            return atoms[key]

        focus = load(focus_key)
        if not focus.valid:
            raise ValueError("reply focus absent")
        ticket_ref = focus.value["primary_ticket_ref"]
        ticket_key = AtomKey.from_token(ticket_ref)
        if ticket_key != attention_ticket_key(namespace, ticket_key.name):
            raise ValueError("reply ticket crosses namespace")
        ticket = load(ticket_key)
        pending = list(ticket.value["source_refs"])
        if not pending or len(pending) > 256:
            raise ValueError("reply ticket source roots invalid")
        seen = set()
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            if len(seen) >= 256:
                raise ValueError("reply source closure exceeds bound")
            key = AtomKey.from_token(ref)
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                raise ValueError("reply source crosses namespace")
            seen.add(ref)
            atom = load(key)
            load(access_key(*namespace.as_tuple, key.owner.subject))
            load(source_correction_head_key(namespace, key.owner.subject))
            record = SourceRecord.from_dict(atom.value)
            pending.extend(source_key(*namespace.as_tuple, parent).token
                           for parent in record.parent_source_ids)
        snapshot = GraphSnapshot(tuple(atoms.values()),
                                 (NamespaceEpoch(*namespace.as_tuple, graph_epoch),))
        qualified = read_qualified_focus_attention_ticket(
            snapshot, namespace, now=now, audience=ingress[0][0],
            purpose="expression")
        if (qualified is None
                or set(snapshot.versions) != set(qualified.read_versions)):
            raise ValueError("reply D07 source closure is not qualified")
        return snapshot, qualified.attention

    def _check_reply(self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
                     now: float, clock_epoch: str | None, *,
                     include_binding: bool) -> bool:
        """Read the original C02, D07, worker and request in one graph snapshot."""
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM "
            "graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] != intent.graph_revision
                or epoch != (intent.graph_epoch,)
                or epochs != (intent.access_epoch, intent.delete_epoch)):
            return False
        requirements_data = _canonical(recovery[1])
        if (type(requirements_data) is not dict
                or requirements_data.get("namespace") != asdict(namespace)):
            return False
        requirements = SnapshotRequirementsV2(**{
            **requirements_data, "namespace": namespace})
        if (requirements.authority_id != intent.authority_id
                or requirements.authority_namespace != intent.namespace
                or requirements.activation_generation !=
                   intent.authority_activation_generation
                or requirements.revocation_epoch != intent.authority_revocation_epoch
                or requirements.deletion_seq != intent.authority_deletion_seq
                or requirements.execution_seq != intent.authority_execution_seq):
            return False
        if (job.work_kind != "reply" or job.effect_id is not None
                or job.phase != "running" or job.fence != intent.worker_fence
                or job.cancel_epoch != 0 or job.lease_holder != intent.subject
                or job.result_ref is not None or job.lease_expires_utc is None
                or not now < min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp())):
            return False
        prep_rows = db.execute(
            "SELECT c02_operation_id,source_ref,c02_receipt_digest,source_id,"
            "source_revision,access_revision,attention_ticket_id,focus_revision,"
            "audience,state,acquire_operation_id,actor,worker_fence,call_id,"
            "model_request_digest,binding_digest,envelope_json,request_json "
            "FROM graph_post_c02_reply_model_preparations_v1 "
            "WHERE bot=? AND persona=? AND job_id=?", ns + (job.job_id,)).fetchall()
        if len(prep_rows) != 1:
            return False
        row = prep_rows[0]
        c02_operation_id, source_ref = row[:2]
        snapshot, attention = self._reply_snapshot(
            db, namespace, source_ref, intent.graph_epoch, now)
        c02 = db.execute(
            "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
            "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            ns + (c02_operation_id,)).fetchone()
        if c02 is None:
            return False
        event = db.execute(
            "SELECT reads,revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (c02[1], c02_operation_id)).fetchone()
        if event is None:
            return False
        from ..runtime_contracts import CommitReceipt
        detail = _canonical(c02[4])
        c02_receipt = CommitReceipt(
            "committed", c02_operation_id, c02[0], c02[1], c02[2], c02[3],
            GraphStore._version_rows(event[0]), GraphStore._version_rows(event[1]),
            (NamespaceEpoch(*ns, event[2]),), tuple(detail["ledger_refs"]),
            tuple(detail["outbox_refs"]))
        inputs = read_current_reply_model_inputs_v1(
            db, self._issuer.resource_issuer, namespace, c02_receipt,
            source_ref, snapshot, attention)
        saved = read_saved_reply_job_v1(
            db, self._issuer.resource_issuer, namespace,
            c02_operation_id, source_ref)
        if saved is None or saved.job != job:
            return False
        quote = saved.quote
        acquire = db.execute(
            "SELECT state,request_digest,attempt_id,anchor_json,"
            "graph_revision,graph_epoch "
            "FROM graph_post_c02_reply_model_acquires_v1 "
            "WHERE bot=? AND persona=? AND acquire_operation_id=? "
            "AND original_operation_id=?",
            ns + (row[10], job.operation_id)).fetchone()
        if (row[2:10] != (
                canonical_digest(asdict(c02_receipt)),
                inputs.source.source.source_id, inputs.source.source_revision,
                inputs.source.access_revision, attention.ticket.ticket_id,
                attention.focus_version.revision, inputs.conversation_ref,
                "acquired")
                or row[11:13] != (intent.subject, intent.worker_fence)
                or row[10] != intent.operation_id
                or acquire is None or acquire[0] != "committed"
                or intent.source_refs != (inputs.source.source.source_id,)
                or intent.source_revisions != ((row[3], row[4]),)
                or intent.access_revisions != ((row[3], row[5]),)):
            return False
        acquired_anchor = RestoreAnchor(**_canonical(acquire[3]))
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,)).fetchone()
        acquire_event = db.execute(
            "SELECT digest,reads,revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (job.activity_id, row[10])).fetchone()
        if (not acquire[1] or not acquire[2]
                or acquired_anchor.authority_id != intent.authority_id
                or acquired_anchor.namespace != intent.namespace
                or acquired_anchor.activation_generation !=
                   intent.authority_activation_generation
                or acquired_anchor.revocation_epoch != intent.authority_revocation_epoch
                or acquired_anchor.deletion_seq != intent.authority_deletion_seq
                or acquired_anchor.execution_seq != intent.authority_execution_seq
                or acquire[4] >= intent.graph_revision
                or acquire[5] >= intent.graph_epoch
                or acquire_event is None
                or job_atom is None or job_atom[2] != 1
                or _canonical(job_atom[1]) != job_graph_write(job).value
                or job_atom[0] != saved.graph_job_revision
                or GraphVersion(job_key, job_atom[0]) not in
                   GraphStore._version_rows(acquire_event[2])
                or acquire_event[3] != acquire[5] + 1
                or acquire_event[3] > intent.graph_epoch):
            return False
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id)).fetchone()
        ceiling = dict(intent.budget_ceiling)
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or reservation != (
                    intent.budget_reservation_digest,
                    canonical_json(ceiling), "reserved")
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id != job.operation_id
                or saved.reservation_digest != intent.budget_reservation_digest
                or quote.ceiling != ceiling
                or quote.graph_job_ref != runtime_job_key(*ns, job.activity_id,
                                                          job.job_id).token
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(key, 0)
                       for key, amount in ceiling.items())
                or any(lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        if not include_binding:
            return True
        if (row[13] != intent.call_id or row[14] != intent.request_digest
                or row[15] != intent.binding_digest
                or row[16] is None or row[17] is None):
            return False
        envelope = reply_envelope_from_wire_v1(row[16])
        frozen = _canonical(row[17])
        archive = db.execute(
            "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (c02_operation_id,)).fetchone()
        guard = envelope.version_guard
        guard_versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')",
            ns).fetchall()
        if (type(frozen) is not dict
                or frozen.get("envelope") != _canonical(canonical_serialize(asdict(envelope)))
                or archive is None
                or envelope.source_qualification !=
                   c02_bundle_from_wire(archive[0]).envelope.source_qualification
                or guard.read_versions != inputs.graph_snapshot.versions
                or guard.query_epochs != (QueryEpoch(namespace, "all", acquire[5]),)
                or (guard.access_epoch, guard.delete_epoch) != epochs
                or guard.source_grant_refs
                or guard.focus_lease_versions != (
                    VersionedRef(attention.ticket_version.key.token,
                                 attention.ticket_version.revision),)
                or guard.resource_lease_versions != (
                    VersionedRef(quote.quote_id, quote.version),)
                or dict(guard_versions) != {
                    "scheme": guard.scheme_version,
                    "operator": guard.operator_version,
                    "policy": guard.policy_version}
                or frozen.get("call_id") != intent.call_id
                or frozen.get("provider_id") != intent.provider_id
                or frozen.get("model_id") != intent.model_id
                or frozen.get("max_output_tokens") != intent.max_output_tokens
                or frozen.get("prompt_template_digest") != REPLY_TEMPLATE_DIGEST):
            return False
        request = issue_reply_request_v1(
            envelope, inputs.source, provider_id=frozen["provider_id"],
            model_id=frozen["model_id"],
            required_capabilities=frozenset(frozen["required_capabilities"]),
            privacy_tier=frozen["privacy_tier"],
            timeout_seconds=frozen["timeout_seconds"],
            max_output_tokens=frozen["max_output_tokens"])
        if (canonical_serialize(reply_request_wire_v1(envelope, request)) != row[17]
                or request.digest != intent.request_digest
                or request.call_id != intent.call_id
                or reply_binding_digest_v1(job, inputs, row[10],
                                           request.call_id, request.digest)
                   != intent.binding_digest
                or envelope.identity.operation_id != row[10]
                or envelope.identity.activity_id != job.activity_id
                or envelope.identity.phase != "post_c02_reply_model"
                or envelope.authority.actor != intent.subject
                or envelope.authority.issuer_domain != "d11"
                or envelope.authority.worker_fence != intent.worker_fence
                or envelope.authority.namespace != namespace
                or envelope.authority.audience != (inputs.conversation_ref,)
                or envelope.authority.activation_generation !=
                   intent.authority_activation_generation
                or envelope.parent_budget_lease_ref != job.budget_ref
                or envelope.deadline_utc != min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp())
                or not now < envelope.deadline_utc):
            return False
        return True

    def _check_context_reply(self, db: sqlite3.Connection,
                             intent: ModelEgressIntentV1, now: float, *,
                             include_binding: bool) -> bool:
        """Reopen the original V2 call and its current D06/D07/budget read set."""
        from ..runtime.context_reply_job_v2 import (
            read_original_context_reply_call_binding_v2,
            read_original_context_reply_preparation_v2,
        )
        from .current_context_reply_source_verifier import (
            read_current_context_reply_sources_v1,
        )

        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        rows = db.execute(
            "SELECT c02_operation_id,source_ref FROM "
            "graph_context_reply_preparations_v2 WHERE bot=? AND persona=? "
            "AND job_id=?", ns + (job.job_id,),
        ).fetchall()
        if len(rows) != 1:
            return False
        c02_operation_id, source_ref = rows[0]
        saved = read_original_context_reply_preparation_v2(
            db, namespace, c02_operation_id, source_ref)
        if saved is None or saved.state != "acquired":
            return False
        seal, frozen = saved.seal, saved.frozen_request
        binding = read_original_context_reply_call_binding_v2(db, saved)
        if binding is None:
            return False
        request = binding.model_call_request
        archive = db.execute(
            "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (c02_operation_id,),
        ).fetchone()
        original_source_id = AtomKey.from_token(source_ref).owner.subject
        ingress = db.execute(
            "SELECT conversation_ref FROM graph_first_ingress_identity_v1 "
            "WHERE bot=? AND persona=? AND source_ref=?",
            ns + (original_source_id,),
        ).fetchall()
        if (archive is None or len(ingress) != 1
                or c02_bundle_from_wire(archive[0]).envelope
                   .source_qualification.source_refs != (source_ref,)
                or ingress[0][0] != frozen.input.conversation_ref
                or frozen.input.audience_ref.ref != ingress[0][0]):
            return False
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM "
            "graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] != intent.graph_revision
                or epoch != (intent.graph_epoch,)
                or epochs != (intent.access_epoch, intent.delete_epoch)):
            return False
        requirement_data = _canonical(recovery[1])
        requirements = SnapshotRequirementsV2(**{
            **requirement_data, "namespace": namespace})
        if (requirement_data.get("namespace") != asdict(namespace)
                or requirements.authority_id != intent.authority_id
                or requirements.authority_namespace != intent.namespace
                or requirements.activation_generation !=
                   intent.authority_activation_generation
                or requirements.revocation_epoch != intent.authority_revocation_epoch
                or requirements.deletion_seq != intent.authority_deletion_seq
                or requirements.execution_seq != intent.authority_execution_seq
                or frozen.input.activation_generation !=
                   requirements.activation_generation):
            return False
        if (job.work_kind != "context_reply" or job.phase != "running"
                or job.effect_id is not None or job.cancel_epoch != 0
                or job.result_ref is not None or job.fence != intent.worker_fence
                or job.fence != binding.worker_fence
                or job.lease_holder != intent.subject
                or job.operation_id != seal.original_operation_id
                or job.lease_expires_utc is None
                or not now < min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    frozen.input.expires_at_utc)):
            return False
        snapshot, attention = self._reply_snapshot(
            db, namespace, source_ref, intent.graph_epoch, now)
        sources = read_current_context_reply_sources_v1(
            db, frozen, now_utc=now)
        if (sources is None
                or set(snapshot.versions) != set(saved.read_versions)
                or not set(sources.read_versions) <= set(snapshot.versions)
                or set(part.ref.ref for part in frozen.input.evidence)
                   != set(attention.ticket.source_refs)
                or source_ref not in attention.ticket.source_refs
                or (saved.access_epoch, saved.delete_epoch) != epochs):
            return False
        original = snapshot.get(AtomKey.from_token(source_ref))
        if (original is None or not original.valid
                or frozen.input.question.text !=
                   SourceRecord.from_dict(original.value).text):
            return False
        source_versions = []
        access_versions = []
        for part in frozen.input.evidence:
            atom = snapshot.get(AtomKey.from_token(part.ref.ref))
            record = SourceRecord.from_dict(atom.value)
            if part.access_ref is None:
                return False
            source_versions.append((record.source_id, part.ref.version))
            access_versions.append((record.source_id, part.access_ref.version))
        if (intent.source_refs != tuple(source_id for source_id, _ in source_versions)
                or intent.source_revisions != tuple(source_versions)
                or intent.access_revisions != tuple(access_versions)):
            return False
        acquire = db.execute(
            "SELECT state,request_digest,anchor_json,graph_revision,graph_epoch "
            "FROM graph_context_reply_acquires_v2 WHERE bot=? AND persona=? "
            "AND acquire_operation_id=?", ns + (seal.acquire_operation_id,),
        ).fetchone()
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,),
        ).fetchone()
        if (acquire is None or acquire[0] != "committed"
                or not acquire[1] or not acquire[2]
                or acquire[3] >= intent.graph_revision
                or acquire[4] >= intent.graph_epoch
                or job_atom is None or job_atom[2] != 1
                or _canonical(job_atom[1]) != job_graph_write(job).value):
            return False
        acquire_event = db.execute(
            "SELECT revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (job.activity_id, seal.acquire_operation_id),
        ).fetchone()
        if (acquire_event is None
                or GraphVersion(job_key, job_atom[0]) not in
                   GraphStore._version_rows(acquire_event[0])
                or acquire_event[1] != acquire[4] + 1
                or acquire_event[1] > intent.graph_epoch):
            return False
        anchor = RestoreAnchor(**_canonical(acquire[2]))
        if (anchor.authority_id != intent.authority_id
                or anchor.namespace != intent.namespace
                or anchor.activation_generation !=
                   intent.authority_activation_generation
                or anchor.revocation_epoch != intent.authority_revocation_epoch
                or anchor.deletion_seq != intent.authority_deletion_seq
                or anchor.execution_seq != intent.authority_execution_seq):
            return False
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
        quote_id = "context-reply-quote:" + seal.job_id.split(":")[-1]
        quote = self._issuer.resource_issuer.original_signed_quote(
            db, quote_id, 1)
        ceiling = dict(intent.budget_ceiling)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id),
        ).fetchone()
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or reservation != (
                    intent.budget_reservation_digest,
                    canonical_json(ceiling), "reserved")
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id != job.operation_id
                or quote.ceiling != ceiling or quote.work_kind != "context_reply"
                or quote.graph_job_ref != job_key.token
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.work_kind not in grant.allowed_work_kinds
                or ceiling.get("output_tokens", 0) < intent.max_output_tokens
                or any(amount > grant.max_ceiling.get(key, 0)
                       or lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        # The original typed call is part of both the proposed intent and
        # final dispatch check. A graph-only preflight cannot accept a draft
        # with somebody else's call identity.
        guard = request.envelope.version_guard
        guard_versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')",
            ns,
        ).fetchall()
        if (intent.operation_id != seal.acquire_operation_id
                or intent.acquire_operation_id != seal.acquire_operation_id
                or intent.call_id != seal.call_id
                or intent.request_digest != binding.model_call_request_digest
                or intent.binding_digest != canonical_digest({
                    "original_seal_digest": canonical_digest(asdict(seal)),
                    "model_call_request_digest": request.digest,
                    "worker_fence": job.fence,
                })
                or intent.provider_id != request.provider_id
                or intent.model_id != request.model_id
                or intent.provider_config_digest != seal.provider_config_digest
                or intent.max_output_tokens != request.max_output_tokens
                or request.identity.phase != "context_reply"
                or request.identity.operation_id != seal.acquire_operation_id
                or request.envelope.authority.actor != intent.subject
                or request.envelope.authority.issuer_domain != "d11"
                or request.envelope.authority.worker_fence != job.fence
                or request.envelope.authority.namespace != namespace
                or request.envelope.authority.audience != (
                    frozen.input.conversation_ref,)
                or request.envelope.authority.purpose != "proposal"
                or request.envelope.parent_budget_lease_ref != job.budget_ref
                or guard.read_versions != saved.read_versions + (
                    GraphVersion(job_key, job_atom[0]),)
                or guard.query_epochs != (QueryEpoch(
                    namespace, saved.query_epoch.scope_ref,
                    intent.graph_epoch),)
                or (guard.access_epoch, guard.delete_epoch) != epochs
                or guard.source_grant_refs or guard.focus_lease_versions
                or guard.resource_lease_versions
                or dict(guard_versions) != {
                    "scheme": guard.scheme_version,
                    "operator": guard.operator_version,
                    "policy": guard.policy_version}
                or not now < request.envelope.deadline_utc):
            return False
        return True

    def _check_natural_stage(self, db: sqlite3.Connection,
                             intent: ModelEgressIntentV1, now: float, *,
                             stage: str, include_binding: bool) -> bool:
        """Reopen one sealed natural stage, private scope and current grant."""
        from ..runtime.natural_generation_issue_v2 import (
            read_original_scoped_query_proof_v2,
        )
        from ..runtime.natural_reply_job_v2 import (
            read_original_call_binding, read_original_preparation,
        )
        from ..runtime.natural_scoped_query_proof_v2 import (
            assert_natural_scoped_query_current_v2,
        )

        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        if stage not in {"generation", "review"}:
            return False
        table = ("graph_natural_generation_preparations_v2" if
                 stage == "generation" else "graph_natural_review_preparations_v2")
        rows = db.execute(
            f"SELECT parent_original_id FROM {table} "
            "WHERE bot=? AND persona=? AND job_id=?", ns + (job.job_id,),
        ).fetchall()
        if len(rows) != 1:
            return False
        saved = read_original_preparation(db, namespace, rows[0][0], stage)
        if saved is None or saved.state != "acquired":
            return False
        generation = (saved if stage == "generation" else
                      read_original_preparation(
                          db, namespace, rows[0][0], "generation"))
        if generation is None or (stage == "review" and
                                  generation.state != "terminal"):
            return False
        seal, frozen = saved.seal, generation.frozen
        from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4
        if type(frozen) is FrozenNaturalReplyRequestV4:
            from .d13_natural_frame_verifier_v1 import InstalledAuthorityD13NaturalFrameVerifierV1
            if (type(self._natural_history) is not InstalledAuthorityD13NaturalFrameVerifierV1
                    or self._natural_history.current_v4(db, frozen=frozen,
                        parent_original_id=generation.seal.c02_operation_id, now_utc=now) is None):
                return False
        binding = read_original_call_binding(db, saved)
        if binding is None:
            return False
        request = binding.request
        proof = read_original_scoped_query_proof_v2(db, generation)
        assert_natural_scoped_query_current_v2(db, proof, now_utc=now)
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM "
            "graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] < intent.graph_revision
                or epoch is None or epoch[0] < intent.graph_epoch
                or epochs != (intent.access_epoch, intent.delete_epoch)
                or epochs != (saved.access_epoch, saved.deletion_epoch)):
            return False
        requirement_data = _canonical(recovery[1])
        requirements = SnapshotRequirementsV2(**{
            **requirement_data, "namespace": namespace})
        if (requirement_data.get("namespace") != asdict(namespace)
                or (requirements.authority_id,
                    requirements.authority_namespace,
                    requirements.activation_generation,
                    requirements.revocation_epoch,
                    requirements.deletion_seq,
                    requirements.execution_seq) !=
                   (intent.authority_id, intent.namespace,
                    intent.authority_activation_generation,
                    intent.authority_revocation_epoch,
                    intent.authority_deletion_seq,
                    intent.authority_execution_seq)):
            return False
        if (job.work_kind != "natural_" + stage or job.phase != "running"
                or job.effect_id is not None or job.cancel_epoch != 0
                or job.result_ref is not None or job.fence != intent.worker_fence
                or job.fence != binding.worker_fence
                or job.lease_holder != intent.subject
                or job.operation_id != seal.original_operation_id
                or job.lease_expires_utc is None
                or not now < min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    frozen.input.expires_at_utc,
                    frozen.input.plan.valid_until_utc)):
            return False
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,),
        ).fetchone()
        if (job_atom is None or job_atom[2] != 1 or job_atom[0] != 2
                or _canonical(job_atom[1]) != job_graph_write(job).value):
            return False
        if (intent.operation_id != seal.acquire_operation_id
                or intent.acquire_operation_id != seal.acquire_operation_id
                or intent.call_id != seal.call_id
                or intent.job_id != seal.job_id
                or intent.request_digest != binding.typed_request_digest
                or intent.binding_digest != canonical_digest({
                    "original_seal_digest": canonical_digest(asdict(seal)),
                    "model_call_request_digest": request.digest,
                    "worker_fence": job.fence,
                })
                or intent.provider_id != request.provider_id
                or intent.model_id != request.model_id
                or intent.provider_config_digest != seal.provider_config_digest
                or intent.max_output_tokens != request.max_output_tokens
                or request.identity.phase != "natural_" + stage
                or request.identity.operation_id != seal.acquire_operation_id
                or request.call_id != seal.call_id
                or request.envelope.authority.actor != intent.subject
                or request.envelope.authority.issuer_domain != "d11"
                or request.envelope.authority.worker_fence != job.fence
                or request.envelope.authority.namespace != namespace
                or request.envelope.authority.audience != (
                    frozen.input.plan.audience_id,)
                or request.envelope.authority.purpose != "proposal"
                or request.envelope.parent_budget_lease_ref != job.budget_ref):
            return False
        guard = request.envelope.version_guard
        guard_versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')",
            ns,
        ).fetchall()
        if (tuple(item.scope_ref for item in guard.query_epochs) != (
                "all", "d03.role_binding", "d05.boundary")
                or any(item.namespace != namespace
                       or not saved.graph_epoch < item.revision <= intent.graph_epoch
                       for item in guard.query_epochs)
                or (guard.access_epoch, guard.delete_epoch) != epochs
                or dict(guard_versions) != {
                    "scheme": guard.scheme_version,
                    "operator": guard.operator_version,
                    "policy": guard.policy_version}
                or guard.source_grant_refs
                or not now < request.envelope.deadline_utc):
            return False
        read_versions = {row.key.token: row.revision
                         for row in guard.read_versions}
        if (len(read_versions) != len(guard.read_versions)
                or read_versions.get(job_key.token) != job_atom[0]
                or any(read_versions.get(item.token) != item.revision
                       for item in (*proof.account_matches, *proof.role_matches,
                                    *proof.boundary_matches, *proof.d06_closure))):
            return False
        for token, revision in read_versions.items():
            row = db.execute(
                "SELECT revision FROM graph_atoms WHERE token=?", (token,),
            ).fetchone()
            if (row[0] if row else 0) != revision:
                return False
        source = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (generation.seal.source_ref,),
        ).fetchone()
        source_id = AtomKey.from_token(generation.seal.source_ref).owner.subject
        access = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (access_key(*ns, source_id).token,),
        ).fetchone()
        if (source is None or source[2] != 1 or access is None or access[1] != 1
                or intent.source_refs != (source_id,)
                or intent.source_revisions != ((source_id, source[0]),)
                or intent.access_revisions != ((source_id, access[0]),)):
            return False
        quote_ref = job.operator_versions["resource_quote"]
        quote_id, quote_version = quote_ref.rsplit(":", 1)
        quote = self._issuer.resource_issuer.original_signed_quote(
            db, quote_id, int(quote_version))
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
        ceiling = dict(intent.budget_ceiling)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, seal.reservation_operation_id),
        ).fetchone()
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or reservation != (
                    intent.budget_reservation_digest,
                    canonical_json(ceiling), "reserved")
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id !=
                   seal.reservation_operation_id
                or quote.ceiling != ceiling or quote.work_kind !=
                   "natural_" + stage
                or quote.operation_id != seal.reservation_operation_id
                or quote.graph_job_ref != job_key.token
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.work_kind not in grant.allowed_work_kinds
                or ceiling.get("output_tokens", 0) < intent.max_output_tokens
                or any(amount > grant.max_ceiling.get(key, 0)
                       or lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        return True

    def _check_binding(self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
                       now: float, clock_epoch: str) -> bool:
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        binding = load_binding(db, namespace, intent.job_id)
        if binding is None:
            return False
        frozen = binding.request
        if frozen.get("schema") not in {
                "sylanne.first-ingress-encoding-call.v2",
                "sylanne.first-ingress-encoding-call.v3"}:
            return False
        acquire = db.execute(
            "SELECT i.acquire_operation_id,i.job_id,i.original_operation_id,"
            "i.actor,i.encoding_binding_json,r.job_json "
            "FROM graph_job_acquire_intents_v2 AS i "
            "JOIN graph_job_acquire_receipts_v2 AS r ON "
            "r.bot=i.bot AND r.persona=i.persona "
            "AND r.acquire_operation_id=i.acquire_operation_id "
            "WHERE i.bot=? AND i.persona=? AND i.job_id=?",
            namespace.as_tuple + (job.job_id,),
        ).fetchall()
        if (len(acquire) != 1 or acquire[0][1:4] != (
                job.job_id, job.operation_id, job.lease_holder)
                or acquire[0][4] != binding_to_json(binding)
                or _canonical(acquire[0][5]) != asdict(job)):
            return False
        acquire_operation_id = acquire[0][0]
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
        baseline_version = ()
        if frozen["schema"] == "sylanne.first-ingress-encoding-call.v3":
            baseline = CommittedEncodingBaselineV1(**frozen["baseline"])
            acquire_stamp = db.execute(
                "SELECT graph_revision,graph_epoch FROM "
                "graph_job_acquire_intents_v2 WHERE bot=? AND persona=? "
                "AND acquire_operation_id=?",
                namespace.as_tuple + (acquire_operation_id,),
            ).fetchone()
            if acquire_stamp is None:
                return False
            recovery = db.execute(
                "SELECT requirements_json,graph_revision FROM "
                "graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            epoch = db.execute(
                "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            if recovery is None or epoch is None:
                return False
            requirements_data = _canonical(recovery[0])
            requirements = SnapshotRequirementsV2(**{
                **requirements_data, "namespace": namespace})
            if not committed_baseline_current(
                    db, namespace=namespace, baseline=baseline,
                    source_id=source_id, requirements=requirements,
                    current_graph_revision=recovery[1],
                    current_graph_epoch=epoch[0],
                    acquire_graph_revision=acquire_stamp[0],
                    acquire_graph_epoch=acquire_stamp[1],
                    issuer=self._issuer):
                return False
            baseline_version = (
                GraphVersion(AtomKey.from_token(baseline.baseline_ref),
                             baseline.baseline_revision),)
        expected_guard = VersionGuard(
            (GraphVersion(source_key(*namespace.as_tuple, source_id), source_row[0]),
             GraphVersion(access_key_value, access_row[0])) + baseline_version, (),
            intent.access_epoch, intent.delete_epoch, catalogue,
            current["scheme"], current["operator"], current["policy"],
            (), (), (),
        )
        original = db.execute(
            "SELECT source_qualification_json,policy_json "
            "FROM runtime_ingress_issuance "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (job.operation_id,),
        ).fetchone()
        if original is None or original[0] is None:
            return False
        issue_policy = _canonical(original[1])
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
            and frozen["job_id"] == job.job_id
            and frozen["acquire_operation_id"] == acquire_operation_id
            and frozen["original_operation_id"] == job.operation_id
            and frozen["budget_reservation_operation_id"] == job.operation_id
            and frozen["budget_lease_id"] == job.budget_ref
            and frozen["work_kind"] == job.work_kind
            and frozen["worker_fence"] == job.fence
            and frozen["worker_lease_expires_utc"] == job.lease_expires_utc
            and frozen["clock_epoch"] == clock_epoch
            and frozen["provider_id"] == intent.provider_id
            and frozen["model_id"] == intent.model_id
            and frozen["provider_config_digest"] == intent.provider_config_digest
            and frozen["max_output_tokens"] == intent.max_output_tokens
            and frozen["prompt_template_version"] == FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
            and frozen["prompt_template_digest"] == template_digest
            and frozen["payload"] == payload
            and envelope["identity"]["operation_id"] == acquire_operation_id
            and envelope["identity"]["phase"] == "encode"
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
            and request_deadline == min(
                datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())
            and envelope["character_interval_ref"] == issue_policy["character_interval_ref"]
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
        # A sibling or descendant may already have spent beyond its original
        # ceiling. The family debt marker is read in this same graph snapshot;
        # a still-reserved local job is not permission for a new model dispatch.
        require_budget_family_admissible(db, job.budget_ref)
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
