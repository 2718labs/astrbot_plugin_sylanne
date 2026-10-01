"""Build a D04 read frame inside W01's live, fenced graph transaction.

The two verifier ports are installed W01 dependencies. A caller supplied
checkpoint, snapshot, certificate string, or boolean is never accepted as
evidence. This reader checks the actual graph rows and source closure; W01
retains responsibility for authenticating its Authority permit and replaying
the numeric adoption with the installed ABI2 implementation. The returned
frame is an input to D04ProductReadoutIssuer, not an adoption credential.
"""

from __future__ import annotations

import json
import sqlite3
import struct
from typing import Protocol

from ...contracts import canonical_json
from ...graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import AuthorityContext, FenceScope, NamespaceId, canonical_digest
from ..d06 import source_correction_head_key
from .affect import AffectScheme, _decode_feeling
from .numeric_coupling import REGISTERED_AXIS_IDS, TYPE_NAME as COUPLING_TYPE
from .product_issuer import D04CurrentProductReadFrameV1, D04VerifiedNumericAdoptionV1
from .root import NumericCheckpoint, decode_numeric_checkpoint
from .source_head import D04SourceHeadRead


CHECKPOINT_TYPE = "d04.numeric_checkpoint.v1"
MAX_SOURCES = 256
MAX_NUMERIC_ROWS = 512


class D04CurrentReadHold(ValueError):
    """A current product read cannot be established from the live transaction."""


class D04CurrentReadAuthority(Protocol):
    def verify_live_read(self, db: sqlite3.Connection, authority: AuthorityContext,
                         fence: FenceScope) -> bool: ...

    def verify_numeric_adoption(
        self, db: sqlite3.Connection, checkpoint: NumericCheckpoint,
        checkpoint_ref: str, checkpoint_revision: int, closure_digest: str,
    ) -> D04VerifiedNumericAdoptionV1: ...


def _atom(db: sqlite3.Connection, key: AtomKey) -> GraphAtom:
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (key.token,),
    ).fetchone()
    if row is None:
        return GraphAtom(key, 0, {}, False)
    try:
        value = json.loads(row[1])
        if canonical_json(value) != row[1] or type(row[0]) is not int or row[0] < 1:
            raise ValueError("noncanonical atom")
    except (TypeError, ValueError) as exc:
        raise D04CurrentReadHold("current graph atom is invalid") from exc
    if row[2] not in (0, 1):
        raise D04CurrentReadHold("current graph atom validity is invalid")
    return GraphAtom(key, row[0], value, bool(row[2]))


def _source_closure(db: sqlite3.Connection, namespace: NamespaceId,
                    source_refs: tuple[str, ...], audience: tuple[str, ...],
                    purpose: str) -> dict[AtomKey, GraphAtom]:
    pending = list(source_refs)
    seen: set[str] = set()
    result: dict[AtomKey, GraphAtom] = {}
    while pending:
        ref = pending.pop()
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise D04CurrentReadHold("source ref is invalid") from exc
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise D04CurrentReadHold("source crosses the current namespace")
        source_id = key.owner.subject
        assert source_id is not None
        if source_id in seen:
            continue
        seen.add(source_id)
        if len(seen) > MAX_SOURCES:
            raise D04CurrentReadHold("source ancestry exceeds bound")
        source = _atom(db, key)
        access = _atom(db, access_key(*namespace.as_tuple, source_id))
        correction = _atom(db, source_correction_head_key(namespace, source_id))
        if (not source.valid or not access.valid or correction.revision != 0
                or correction.valid):
            raise D04CurrentReadHold("source is missing, revoked or corrected")
        try:
            record = SourceRecord.from_dict(source.value)
            validate_access(access.value)
        except (TypeError, ValueError) as exc:
            raise D04CurrentReadHold("source or access record is invalid") from exc
        if (record.source_id != source_id or access.value["source_id"] != source_id
                or access.value["status"] != "active"
                or purpose not in record.purposes or purpose not in access.value["purposes"]
                or not set(audience).issubset(record.audiences)
                or not set(audience).issubset(access.value["audiences"])):
            raise D04CurrentReadHold("source purpose or audience is not authorized")
        result.update((atom.key, atom) for atom in (source, access, correction))
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in record.parent_source_ids)
    return result


def read_d04_current_product_frame_in_transaction(
    db: sqlite3.Connection, *, authority: AuthorityContext, fence: FenceScope,
    verifier: D04CurrentReadAuthority, checkpoint_ref: str, source_ref: str,
    audience: tuple[str, ...], purpose: str, installed_scheme: AffectScheme,
    installed_scheme_sha256: str,
) -> D04CurrentProductReadFrameV1:
    """Read one isolated 24D feeling block under W01's existing transaction.

    W01 supplies a verifier backed by its live Authority v2 fence and installed
    numeric issuer. In particular, verify_numeric_adoption must recheck the
    persisted commit receipt and native certificate, including inherited error.
    It must fail closed for the currently unsupported root/advance provenance.
    """
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise D04CurrentReadHold("D04 current read requires W01's graph transaction")
    if (type(authority) is not AuthorityContext or type(fence) is not FenceScope
            or type(installed_scheme) is not AffectScheme
            or not callable(getattr(verifier, "verify_live_read", None))
            or not callable(getattr(verifier, "verify_numeric_adoption", None))):
        raise TypeError("D04 current read needs typed installed W01 dependencies")
    namespace = authority.namespace
    if (fence.operation != "read" or fence.namespace != namespace
            or fence.generation != authority.activation_generation
            or "persona" not in authority.owner_scope
            or type(audience) is not tuple or not audience
            or any(type(item) is not str or not item or item == "*" for item in audience)
            or not set(audience).issubset(authority.audience)
            or purpose != authority.purpose
            or installed_scheme_sha256 is None):
        raise D04CurrentReadHold("D04 Authority or installed Scheme scope differs")
    if verifier.verify_live_read(db, authority, fence) is not True:
        raise D04CurrentReadHold("live Authority read fence is unavailable")
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       namespace.as_tuple).fetchone()
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    recovery = db.execute(
        "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (epoch != (fence.graph_epoch.revision,) or epochs is None or recovery is None
            or recovery[1] != fence.graph_revision):
        raise D04CurrentReadHold("graph or Authority epoch changed")
    try:
        requirements = json.loads(recovery[0])
        incarnation = requirements["graph_incarnation"]
        if type(incarnation) is not str or not incarnation:
            raise ValueError("missing incarnation")
    except (TypeError, ValueError, KeyError) as exc:
        raise D04CurrentReadHold("graph incarnation is unavailable") from exc
    try:
        key = AtomKey.from_token(checkpoint_ref)
        selected_source = AtomKey.from_token(source_ref)
    except (TypeError, ValueError) as exc:
        raise D04CurrentReadHold("checkpoint or source ref is invalid") from exc
    if (key.type_name != CHECKPOINT_TYPE or key.owner.kind != "persona"
            or NamespaceId.from_key(key) != namespace
            or selected_source != source_key(*namespace.as_tuple,
                                             selected_source.owner.subject or "")):
        raise D04CurrentReadHold("checkpoint or source crosses namespace")
    checkpoint_atom = _atom(db, key)
    if not checkpoint_atom.valid:
        raise D04CurrentReadHold("current numeric checkpoint is absent")
    try:
        checkpoint = decode_numeric_checkpoint(checkpoint_atom.value)
    except (TypeError, ValueError) as exc:
        raise D04CurrentReadHold("current numeric checkpoint is invalid") from exc
    if (checkpoint.namespace != namespace.as_tuple or checkpoint.block.kind != "feeling"
            or checkpoint.block.block_id != key.name
            or checkpoint.axes != REGISTERED_AXIS_IDS
            or checkpoint.assets.scheme_sha256 != installed_scheme_sha256
            or tuple(axis.axis_id for axis in installed_scheme.axes) != checkpoint.axes
            or any(getattr(checkpoint.assets, name) != getattr(installed_scheme, name)
                   for name in ("scheme_version", "operator_version",
                                "parameter_version", "coupling_version"))):
        raise D04CurrentReadHold("checkpoint and installed Scheme differ")
    for kind, version in (("scheme", installed_scheme.scheme_version),
                          ("operator", installed_scheme.operator_version)):
        guard = db.execute(
            "SELECT version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND kind=? AND ref='current'", namespace.as_tuple + (kind,),
        ).fetchone()
        if guard != (version,):
            raise D04CurrentReadHold("installed Scheme graph guard changed")
    state_key = AtomKey.from_token(checkpoint.graph_state.ref)
    state = _atom(db, state_key)
    if not state.valid or state.revision != checkpoint.graph_state.revision:
        raise D04CurrentReadHold("feeling state is stale")
    try:
        feeling = _decode_feeling(state.value)
    except (TypeError, ValueError) as exc:
        raise D04CurrentReadHold("feeling state is invalid") from exc
    if (feeling.process_id != checkpoint.block.block_id
            or feeling.target_ref != checkpoint.block.object_ref
            or feeling.meaning_refs != (checkpoint.block.meaning_ref,)
            or feeling.revision != state.revision
            or feeling.cursor != checkpoint.cursor
            or feeling.basis_version != checkpoint.assets.scheme_version
            or feeling.operator_version != checkpoint.assets.operator_version
            or feeling.parameter_version != checkpoint.assets.parameter_version
            or feeling.coupling_version != checkpoint.assets.coupling_version
            or tuple(axis for axis, _ in feeling.coordinates) != checkpoint.axes
            or any(struct.pack("!d", value) != struct.pack("!d", expected)
                   for (_, value), expected in zip(feeling.coordinates,
                                                   checkpoint.latent_state))
            or source_ref not in feeling.historical_source_refs):
        raise D04CurrentReadHold("feeling and numeric state differ")
    authored = source_key(*namespace.as_tuple, checkpoint.block.authored_source_id).token
    if (authored not in feeling.historical_source_refs
            or not feeling.historical_source_refs):
        raise D04CurrentReadHold("authored source is absent from feeling lineage")
    # The existing C06 candidate assigns every output to one source_ref. It
    # cannot justify that attribution when other sources, interpretations or
    # active drivers have contributed to the same 24D block. A future causal
    # allocation proof must replace this restriction for richer mixed blocks.
    if (feeling.historical_source_refs != (source_ref,)
            or len(feeling.interpretation_refs) != 1
            or feeling.active_driver_refs):
        raise D04CurrentReadHold("mixed feeling lacks single-source causal qualification")
    # The present fixed ABI2 readout covers one independent block. Any live
    # coupling touching it requires a joint certificate that this path lacks.
    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name IN (?,?) ORDER BY token LIMIT ?",
        namespace.as_tuple + (CHECKPOINT_TYPE, COUPLING_TYPE, MAX_NUMERIC_ROWS + 1),
    ).fetchall()
    if len(rows) > MAX_NUMERIC_ROWS:
        raise D04CurrentReadHold("numeric topology exceeds complete scan bound")
    from .numeric_coupling import validate_numeric_coupling
    for token, revision, encoded, valid in rows:
        row_key = AtomKey.from_token(token)
        if NamespaceId.from_key(row_key) != namespace:
            raise D04CurrentReadHold("numeric topology crosses namespace")
        if row_key.type_name == COUPLING_TYPE and valid:
            try:
                edge = validate_numeric_coupling(json.loads(encoded), installed_scheme)
            except (TypeError, ValueError) as exc:
                raise D04CurrentReadHold("numeric coupling is invalid") from exc
            if checkpoint_ref in (edge.left_ref, edge.right_ref):
                raise D04CurrentReadHold("mixed block needs a joint SCC certificate")
    sources = _source_closure(db, namespace, feeling.historical_source_refs,
                              audience, purpose)
    atoms = {atom.key: atom for atom in (checkpoint_atom, state)}
    atoms.update(sources)
    snapshot = GraphSnapshot(tuple(atoms.values()), (fence.graph_epoch,))
    read = D04SourceHeadRead(snapshot, namespace, audience, purpose,
                             fence, True, True, True)
    closure_digest = canonical_digest(tuple(sorted(
        (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in snapshot.atoms
    )))
    adoption = verifier.verify_numeric_adoption(
        db, checkpoint, checkpoint_ref, checkpoint_atom.revision, closure_digest,
    )
    if (type(adoption) is not D04VerifiedNumericAdoptionV1
            or adoption.status != "coordinator_verified_adoption"
            or adoption.checkpoint_ref != checkpoint_ref
            or adoption.checkpoint_revision != checkpoint_atom.revision
            or adoption.commit_operation_id != checkpoint.commit_operation_id
            or adoption.certificate_source != checkpoint.certificate_source
            or adoption.certificate_digest != checkpoint.certificate_digest
            or adoption.asset_digest != checkpoint.asset_digest
            or adoption.numeric_error_bound != checkpoint.numeric_error_bound
            or adoption.graph_closure_digest != closure_digest
            or not adoption.commit_receipt_digest):
        raise D04CurrentReadHold("numeric adoption certificate is unavailable")
    return D04CurrentProductReadFrameV1(
        checkpoint, checkpoint_ref, checkpoint_atom.revision, source_ref,
        read, installed_scheme, adoption, incarnation, fence.graph_revision,
        epochs[0], epochs[1],
    )


__all__ = ["D04CurrentReadAuthority", "D04CurrentReadHold",
           "read_d04_current_product_frame_in_transaction"]
