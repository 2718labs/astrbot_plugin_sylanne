"""Independent installed C04 current closure read performed under its own gate."""
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from ..runtime_contracts import NamespaceId, canonical_digest
from .contract import AuthorityUnavailable


@dataclass(frozen=True, slots=True)
class C04CurrentExecutionReadV3:
    prepared: object
    actor: str
    grant_value: dict
    requirements: dict
    deadline_utc: float
    current_self: object | None = None
    reply_scope: object | None = None


class InstalledC04CurrentReaderV3:
    def __init__(self, *, namespace, graph_path, resource_issuer, budget_issuer, foreground_observer=None):
        from ..runtime.issuers import D02ResourceIssuer, D11BudgetGrantIssuer
        if (type(namespace) is not NamespaceId or not isinstance(resource_issuer, D02ResourceIssuer)
                or not isinstance(budget_issuer, D11BudgetGrantIssuer)):
            raise AuthorityUnavailable("C04 independent current issuer composition is required")
        self.namespace, self.graph_path = namespace, Path(graph_path).resolve(strict=True)
        self.resource_issuer, self.budget_issuer = resource_issuer, budget_issuer
        self.foreground_observer = None
        if foreground_observer is not None:
            self.install_foreground_observer(foreground_observer)

    def install_foreground_observer(self, foreground_observer):
        from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
        if (type(foreground_observer) is not InstalledCurrentForegroundActivityV1
                or foreground_observer.self_identity._namespace_id != self.namespace
                or foreground_observer.self_identity._graph._path != self.graph_path
                or foreground_observer.issuer.resource_issuer is not self.resource_issuer
                or foreground_observer.installed_bundle is None
                or self.foreground_observer not in (None, foreground_observer)):
            raise AuthorityUnavailable("C04 Self observer crossed its actual installed graph/issuer")
        self.foreground_observer = foreground_observer

    def read_current(self, binding, anchor, *, credential=None, permit=None):
        from ..runtime.c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        from ..runtime.c04_frozen_association_original_v3 import (
            read_c04_frozen_association_original_v3, read_c04_frozen_association_original_v4,
            verify_current_association_input_heads_v3, _verify_current_association_input_heads_common_v3)
        from ..runtime.c04_product_original_v3 import read_c04_product_request_v3
        from ..runtime.c04_prepare_service_v3 import c04_prepare_job_id_v3
        from ..runtime.jobs import get_job
        from ..runtime.budget import get_budget_lease, require_budget_family_admissible
        from ..graph_types import validate_owner_grant_v1
        from ..host.installed_d06_build import ALGORITHM_ID_V3, ALGORITHM_ID_V4
        if binding.algorithm_ref not in {ALGORITHM_ID_V3, ALGORITHM_ID_V4}:
            raise AuthorityUnavailable("C04 current reader has no installed algorithm route")
        current_self = reply_scope = None
        if binding.algorithm_ref == ALGORITHM_ID_V4:
            observer = self.foreground_observer
            if observer is None or permit is None or permit.pinned_anchor != anchor:
                raise AuthorityUnavailable("Self C04 requires its actual independent observer/claim permit")
            current_self = observer.self_identity.current_for_c04_v4(
                credential=credential, reader=self, binding=binding, permit=permit)
            if current_self is None:
                raise AuthorityUnavailable("Self C04 current identity is absent")
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            prepared = read_c04_internal_work_prepared_v1(db, self.namespace, binding.operation_id)
            work = (read_c04_frozen_association_original_v4(db, self.namespace, binding)
                    if binding.algorithm_ref == ALGORITHM_ID_V4 else
                    read_c04_frozen_association_original_v3(db, self.namespace, binding))
            request = read_c04_product_request_v3(db, self.namespace, binding.operation_id)
            if prepared is None or prepared.binding != binding or work is None or request is None:
                raise ValueError("C04 actual prepared input/product original is absent")
            if binding.algorithm_ref == ALGORITHM_ID_V4:
                _verify_current_association_input_heads_common_v3(db, work)
            else:
                verify_current_association_input_heads_v3(db, work)
            for ref, revision in prepared.read_versions:
                row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
                if (row is not None if revision == 0 else row != (revision, 1)):
                    raise ValueError("C04 prepared prerequisite changed before claim")
            metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", self.namespace.as_tuple).fetchone()
            requirements = json.loads(metadata[0]) if metadata else {}
            expected = {"authority_id": anchor.authority_id, "authority_namespace": anchor.namespace,
                "activation_generation": anchor.activation_generation, "revocation_epoch": anchor.revocation_epoch,
                **{name: getattr(anchor, name) for name in ("deletion_journal_id", "deletion_seq", "deletion_digest",
                    "execution_journal_id", "execution_seq", "execution_digest")}}
            if (metadata is None or metadata[1] != prepared.graph_revision
                    or any(requirements.get(k) != v for k, v in expected.items())):
                raise ValueError("C04 actual Graph does not match its exclusive current anchor")
            grant_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (prepared.owner_grant_ref,)).fetchone()
            if grant_row is None or grant_row[0] != prepared.owner_grant_revision or grant_row[2] != 1:
                raise ValueError("C04 current Owner Graph grant is absent")
            grant_value = json.loads(grant_row[1]); validate_owner_grant_v1(grant_value)
            if canonical_digest(grant_value) != prepared.owner_grant_digest:
                raise ValueError("C04 current Owner grant differs from its original")
            quote = self.resource_issuer.original_signed_quote(db, binding.resource_quote_ref, binding.resource_quote_version)
            grant = self.budget_issuer.current_budget_grant(db, binding.parent_budget_lease_ref)
            budget = get_budget_lease(db, binding.parent_budget_lease_ref)
            reserve = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
                "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
                (*self.namespace.as_tuple, prepared.budget_reservation_operation_id)).fetchone()
            reservation = db.execute("SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (binding.parent_budget_lease_ref, prepared.budget_reservation_operation_id)).fetchone()
            now = time.time()
            if (canonical_digest(quote) != binding.resource_quote_digest
                    or quote.work_kind != "d06.c04_internal_cpu.v1" or quote.operation_id != binding.operation_id
                    or quote.activity_id != binding.activity_id or quote.parent_budget_lease_ref != budget.lease_id
                    or (quote.bot_id, quote.persona_id) != self.namespace.as_tuple
                    or quote.work_kind not in grant.allowed_work_kinds or grant.valid_until_utc <= now
                    or grant.lease_id != budget.lease_id or budget.state != "active"
                    or any(v > grant.max_ceiling.get(k, 0) for k, v in quote.ceiling.items())
                    or reserve is None or reserve[:2] != (binding.binding_digest, budget.lease_id)
                    or hashlib.sha256(reserve[2].encode()).hexdigest() != prepared.budget_reservation_digest
                    or reservation != ("reserved",)):
                raise ValueError("C04 current signed CPU quote/grant/reservation is unavailable")
            require_budget_family_admissible(db, budget.lease_id)
            job = get_job(db, c04_prepare_job_id_v3(self.namespace, binding.operation_id))
            deadline = min(request.envelope.deadline_utc, quote.valid_until_utc, grant.valid_until_utc,
                datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp())
            stable_job = job.continuation.get("schema") == "c04.prepared-job-continuation.v4"
            if (job.cancel_epoch != 0 or job.phase not in {"queued", "running"} or now >= deadline
                    or job.operation_id != binding.operation_id or job.budget_ref != binding.parent_budget_lease_ref
                    or (not stable_job and job.continuation.get("binding_digest") != binding.binding_digest)):
                raise ValueError("C04 actual worker was cancelled, changed or expired")
            if stable_job:
                from ..runtime.d11_types import job_graph_write
                from ..runtime.c04_product_lifecycle_v3 import read_original_c04_product_job_v3
                if read_original_c04_product_job_v3(db, self.namespace, prepared) != job:
                    raise ValueError("C04 stable running-job original differs")
                write = job_graph_write(job)
                projection = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
                if (job.phase != "running" or job.fence != 1 or job.lease_holder is None or job.lease_expires_utc is None
                        or now >= datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp()
                        or projection is None or projection[0] != 1 or projection[2] != 1
                        or json.loads(projection[1]) != write.value
                        or (write.key.token, 1) not in prepared.read_versions):
                    raise ValueError("C04 first claim lost its exact prepared running worker")
            if binding.algorithm_ref == ALGORITHM_ID_V4:
                from ..runtime.c04_ingress_preparation_v4 import require_current_self_c04_parent_v4
                observer = self.foreground_observer
                require_current_self_c04_parent_v4(db, namespace=self.namespace,
                    binding=binding, work=work, prepared=prepared,
                    installed_bundle=observer.installed_bundle, issuer=observer.issuer,
                    current_self=current_self, now_utc=now)
                if request.envelope.authority.actor != current_self.self_entity_ref:
                    raise AuthorityUnavailable("Self C04 request actor differs from actual mapping")
                stop = observer._owner_stop_reply_service_v1
                if stop is None:
                    raise AuthorityUnavailable("Self C04 has no actual StopReply barrier")
                # Scope observation opens its own Graph read; leave this snapshot first.
                db.commit()
                reply_scope = stop.observe_actual_reply_scope_v1(
                    c02_operation_id=work.direct_selection.c02_operation_id)
            return C04CurrentExecutionReadV3(prepared, request.envelope.authority.actor,
                grant_value, requirements, deadline, current_self, reply_scope)
        finally:
            db.close()
