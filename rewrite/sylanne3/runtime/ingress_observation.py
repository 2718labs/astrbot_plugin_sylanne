"""Durable first-observation ledger for trusted host ingress.

This module is host-only.  It currently uses GraphCoordinator's internal
business-connection guards because no public observation-write port exists.
Keep it paired with the exact coordinator/store instance; a future public port
should replace this coupling before third-party implementations are supported.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from typing import Callable

from ..contracts import EventConflict, StaleRead
from ..contracts import canonical_json
from ..graph_types import IngressIdentityReceipt
from ..graph_coordinator import (
    AuthorityDenied, GraphCoordinator, _operation_capability_ref,
)
from ..graph_store import ProductionGraphStore
from ..runtime_contracts import NamespaceId
from .first_ingress_v2 import ingress_ids
from .ingress_contracts import (
    CanonicalIngressObservation,
    CommittedIngressReplay,
    IngressAuthoritySession,
    IngressObservationContext,
)


def _digest(value: str, label: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def read_committed_ingress_identity(db, namespace: NamespaceId,
                                    source_ref: str) -> IngressIdentityReceipt | None:
    """Read original host identity inside the coordinator's current DB fence.

    A missing v1 identity is a legacy HOLD. Callers must never fill it from a
    proposal. The D03 provider independently checks the returned tuple against
    its current source and scene.
    """
    if type(namespace) is not NamespaceId:
        raise TypeError("ingress receipt namespace is required")
    _digest(source_ref, "source ref")
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='graph_first_ingress_identity_v1'").fetchone()
    if exists is None:
        return None
    operation_id = ingress_ids(source_ref)[2]
    from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3
    def point(table,columns,legacy_reader):
        return model_reply_scope_point_v3(db,table=table,columns=columns,
            key_columns=('bot','persona','operation_id'),key=namespace.as_tuple+(operation_id,),legacy_reader=legacy_reader)
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    bound,row=read_bound_authority_graph_attachment_v3(db,table='graph_first_ingress_identity_v1',
        columns=('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','identity_json',
            'content_fingerprint','learned_at','bundle_digest'),key_columns=('bot','persona','operation_id'),
        key=namespace.as_tuple+(operation_id,))
    if not bound:
        row = point('graph_first_ingress_identity_v1',
            ('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','identity_json',
                'content_fingerprint','learned_at','bundle_digest'),lambda:db.execute(
            "SELECT source_ref,platform_ref,conversation_ref,sender_ref,message_id,"
            "visibility,identity_json,content_fingerprint,learned_at,bundle_digest "
            "FROM graph_first_ingress_identity_v1 WHERE bot=? AND persona=? "
            "AND operation_id=?",namespace.as_tuple+(operation_id,)).fetchone())
    if row is None:
        return None
    try:
        identity = background_json_loads_v3(row[6])
        valid = (
            type(identity) is dict and set(identity) == {
                "schema", "namespace", "operation_id", "source_ref",
                "platform_ref", "conversation_ref", "sender_ref", "message_id",
                "visibility", "lineage"}
            and identity["schema"] == "sylanne3.ingress.identity.v1"
            and identity["namespace"] == list(namespace.as_tuple)
            and identity["operation_id"] == operation_id
            and tuple(identity[name] for name in (
                "source_ref", "platform_ref", "conversation_ref", "sender_ref",
                "message_id", "visibility")) == row[:6]
            and identity["source_ref"] == source_ref
            and (canonical_json(identity)==row[6]if type(row[6])is str else background_json_matches_v3(row[6],identity))
        )
    except (TypeError, ValueError, KeyError):
        valid = False
    observed = point('ingress_first_observations',('content_fingerprint','learned_at','bundle_digest'),lambda:db.execute(
        "SELECT content_fingerprint,learned_at,bundle_digest FROM ingress_first_observations "
        "WHERE bot=? AND persona=? AND operation_id=?",namespace.as_tuple+(operation_id,)).fetchone())
    committed = point('graph_bundle_operations',('digest',),lambda:db.execute(
        "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple+(operation_id,)).fetchone())
    bound,intent=read_bound_authority_graph_attachment_v3(db,table='graph_first_ingress_intents_v2',
        columns=('identity_json',),key_columns=('bot','persona','operation_id'),key=namespace.as_tuple+(operation_id,))
    if not bound:
        intent = point('graph_first_ingress_intents_v2',('identity_json',),lambda:db.execute(
            "SELECT identity_json FROM graph_first_ingress_intents_v2 WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple+(operation_id,)).fetchone())
    try:
        pinned_fingerprint = background_json_loads_v3(intent[0])["fingerprint"] if intent else None
    except (TypeError, ValueError, KeyError):
        pinned_fingerprint = None
    if (not valid or observed != row[7:10] or committed != (row[9],)
            or pinned_fingerprint != row[7]):
        raise EventConflict("committed ingress identity differs from original")
    return IngressIdentityReceipt(canonical_json(identity), row[7], row[8], row[9])


async def _run_durable(operation, *args):
    """A dispatched durable write must yield its actual result, even if cancelled.

    Cancelling ``to_thread`` only abandons the await; it cannot stop a worker
    that may already be inside SQLite.  Shield and drain that worker so the
    caller never observes cancellation while its write is still unresolved.
    """

    worker = asyncio.create_task(asyncio.to_thread(operation, *args))
    while True:
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            if worker.done():
                return worker.result()


class GraphIngressObservationAuthority:
    """Store W01 ingress observations in the coordinator's business database.

    The injected clock belongs to trusted host setup.  ``observe_first``
    deliberately ignores the envelope's proposed ``learned_at``; chat content
    and replayed host envelopes cannot set the canonical receipt time.
    """

    def __init__(self, coordinator: GraphCoordinator,
                 store: ProductionGraphStore,
                 trusted_clock: Callable[[], float]) -> None:
        if not isinstance(coordinator, GraphCoordinator):
            raise TypeError("GraphCoordinator required")
        if not isinstance(store, ProductionGraphStore):
            raise TypeError("production graph store required")
        # This identity check prevents a valid lease on one coordinator from
        # writing an unrelated SQLite file.  It is an internal integration
        # boundary, not a stable public coordinator API.
        if getattr(coordinator, "_GraphCoordinator__store", None) is not store:
            raise ValueError("observation store differs from coordinator store")
        if not callable(trusted_clock):
            raise TypeError("trusted host clock required")
        self._coordinator = coordinator
        self._store = store
        self._trusted_clock = trusted_clock

    def _ensure_schema(self) -> None:
        """Run only inside an admitted write fence and SQLite transaction."""
        db = self._store._db
        db.execute("""
            CREATE TABLE IF NOT EXISTS ingress_first_observations (
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                content_fingerprint TEXT NOT NULL,
                learned_at REAL NOT NULL CHECK(learned_at > 0),
                bundle_digest TEXT,
                PRIMARY KEY(bot, persona, operation_id)
            )
        """)
        expected = (
            "bot", "persona", "operation_id", "content_fingerprint",
            "learned_at", "bundle_digest",
        )
        columns = tuple(row[1] for row in db.execute(
            "PRAGMA table_info(ingress_first_observations)"))
        if columns != expected:
            raise RuntimeError("ingress observation schema is incompatible")

    @staticmethod
    def _record_ref(context: IngressObservationContext) -> str:
        raw = "\x00".join((*context.namespace.as_tuple, context.operation_id))
        return "ingress:first:sha256:" + hashlib.sha256(raw.encode()).hexdigest()

    def _validate_session(self, context: IngressObservationContext,
                          session: IngressAuthoritySession) -> None:
        if not isinstance(context, IngressObservationContext):
            raise TypeError("IngressObservationContext required")
        context.require_session(session)
        self._coordinator._authorize(session.lease, session.authority,
                                     frozenset({"d06", "d11"}))
        authority = session.authority
        if authority.capability_ref != _operation_capability_ref(
                context.namespace, authority.actor, authority.issuer_domain,
                frozenset({"d06", "d11"}), context.activation_generation,
                context.operation_id):
            raise AuthorityDenied("ingress lease is not scoped to this operation")

    def _active_write(self, context: IngressObservationContext) -> None:
        coordinator = self._coordinator
        coordinator._admit_content(context.namespace, context.activation_generation,
                                   "write")
        if coordinator._version(self._store._db, context.namespace,
                                "activation", "current") != str(context.activation_generation):
            raise StaleRead("activation generation changed")

    def _row(self, context: IngressObservationContext):
        return self._store._db.execute(
            "SELECT content_fingerprint,learned_at,bundle_digest "
            "FROM ingress_first_observations WHERE bot=? AND persona=? "
            "AND operation_id=?",
            context.namespace.as_tuple + (context.operation_id,),
        ).fetchone()

    def _committed_digest(self, context: IngressObservationContext) -> str | None:
        row = self._store._db.execute(
            "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
            "AND operation_id=?",
            context.namespace.as_tuple + (context.operation_id,),
        ).fetchone()
        return None if row is None else row[0]

    async def lookup_committed(self, context: IngressObservationContext,
                               session: IngressAuthoritySession,
                               content_fingerprint: str) -> CommittedIngressReplay | None:
        return await _run_durable(
            self._lookup_committed_sync, context, session, content_fingerprint)

    def _lookup_committed_sync(self, context: IngressObservationContext,
                               session: IngressAuthoritySession,
                               content_fingerprint: str) -> CommittedIngressReplay | None:
        self._validate_session(context, session)
        _digest(content_fingerprint, "content fingerprint")
        receipt = self._coordinator.get_operation(
            session.authority, session.lease, context.operation_id)
        if receipt is None:
            return None
        if receipt.status != "committed" or receipt.operation_id != context.operation_id:
            raise EventConflict("coordinator did not confirm the ingress operation")
        coordinator = self._coordinator
        with coordinator._content_fence(
                context.namespace, context.activation_generation, "read"):
            store = self._store
            with store._lock:
                store._ensure_open()
                coordinator._admit_content(
                    context.namespace, context.activation_generation, "read")
                if coordinator._version(store._db, context.namespace,
                                        "activation", "current") != str(
                                            context.activation_generation):
                    raise StaleRead("activation generation changed")
                exists = store._db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='ingress_first_observations'").fetchone()
                if exists is None:
                    raise EventConflict("committed ingress lacks first observation table")
                row = self._row(context)
                if row is None or row[0] != content_fingerprint:
                    raise EventConflict("committed ingress content fingerprint changed")
                if row[2] != receipt.operation_digest or self._committed_digest(
                        context) != receipt.operation_digest:
                    raise EventConflict("committed ingress differs from sealed bundle")
                observation = CanonicalIngressObservation(
                    context.operation_id, row[0], row[1], self._record_ref(context))
                return CommittedIngressReplay(receipt, observation, session)

    async def observe_first(self, context: IngressObservationContext,
                            session: IngressAuthoritySession,
                            content_fingerprint: str,
                            learned_at: float) -> CanonicalIngressObservation:
        return await _run_durable(
            self._observe_first_sync, context, session, content_fingerprint,
            learned_at)

    def _observe_first_sync(self, context: IngressObservationContext,
                            session: IngressAuthoritySession,
                            content_fingerprint: str,
                            learned_at: float) -> CanonicalIngressObservation:
        self._validate_session(context, session)
        _digest(content_fingerprint, "content fingerprint")
        # Validate the request shape but never trust its proposed clock value.
        if (isinstance(learned_at, bool) or not isinstance(learned_at, (int, float))
                or not math.isfinite(learned_at) or learned_at <= 0):
            raise ValueError("proposed learned_at must be finite and positive")
        # Resolve uncertain commits before the assembler builds a new bundle.
        committed = self._coordinator.get_operation(
            session.authority, session.lease, context.operation_id)
        with self._coordinator._content_fence(
                context.namespace, context.activation_generation, "write"):
            store = self._store
            with store._lock:
                store._ensure_open()
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    self._active_write(context)
                    self._ensure_schema()
                    row = self._row(context)
                    current_commit = self._committed_digest(context)
                    if committed is not None and current_commit != committed.operation_digest:
                        raise EventConflict("ingress commit changed during observation")
                    if row is None:
                        if current_commit is not None:
                            raise EventConflict("committed ingress lacks first observation")
                        canonical_time = float(self._trusted_clock())
                        if not math.isfinite(canonical_time) or canonical_time <= 0:
                            raise ValueError("trusted host clock is unavailable")
                        store._db.execute(
                            "INSERT INTO ingress_first_observations "
                            "(bot,persona,operation_id,content_fingerprint,learned_at) "
                            "VALUES(?,?,?,?,?)",
                            context.namespace.as_tuple + (
                                context.operation_id, content_fingerprint, canonical_time),
                        )
                        row = (content_fingerprint, canonical_time, None)
                    elif row[0] != content_fingerprint:
                        raise EventConflict("operation content fingerprint changed")
                    if current_commit is not None and row[2] != current_commit:
                        raise EventConflict("committed ingress differs from sealed bundle")
                    observation = CanonicalIngressObservation(
                        context.operation_id, row[0], row[1], self._record_ref(context))
                    store._db.execute("COMMIT")
                    return observation
                except BaseException:
                    if store._db.in_transaction:
                        store._db.execute("ROLLBACK")
                    raise

    async def seal_bundle(self, context: IngressObservationContext,
                          session: IngressAuthoritySession,
                          observation: CanonicalIngressObservation,
                          bundle_digest: str) -> str:
        return await _run_durable(
            self._seal_bundle_sync, context, session, observation, bundle_digest)

    def _seal_bundle_sync(self, context: IngressObservationContext,
                          session: IngressAuthoritySession,
                          observation: CanonicalIngressObservation,
                          bundle_digest: str) -> str:
        self._validate_session(context, session)
        _digest(bundle_digest, "bundle digest")
        if (not isinstance(observation, CanonicalIngressObservation)
                or observation.operation_id != context.operation_id
                or observation.durable_record_ref != self._record_ref(context)):
            raise ValueError("observation is not bound to this operation")
        committed = self._coordinator.get_operation(
            session.authority, session.lease, context.operation_id)
        with self._coordinator._content_fence(
                context.namespace, context.activation_generation, "write"):
            store = self._store
            with store._lock:
                store._ensure_open()
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    self._active_write(context)
                    self._ensure_schema()
                    row = self._row(context)
                    current_commit = self._committed_digest(context)
                    if committed is not None and current_commit != committed.operation_digest:
                        raise EventConflict("ingress commit changed during sealing")
                    if row is None or (row[0], row[1]) != (
                            observation.content_fingerprint, observation.learned_at):
                        raise EventConflict("first observation changed or is absent")
                    if current_commit is not None and current_commit != bundle_digest:
                        raise EventConflict("committed ingress bundle differs")
                    if row[2] is None:
                        store._db.execute(
                            "UPDATE ingress_first_observations SET bundle_digest=? "
                            "WHERE bot=? AND persona=? AND operation_id=?",
                            (bundle_digest,) + context.namespace.as_tuple +
                            (context.operation_id,),
                        )
                        sealed = bundle_digest
                    else:
                        sealed = row[2]
                    store._db.execute("COMMIT")
                    return sealed
                except BaseException:
                    if store._db.in_transaction:
                        store._db.execute("ROLLBACK")
                    raise


__all__ = ("GraphIngressObservationAuthority", "read_committed_ingress_identity")
