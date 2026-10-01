"""D11 signed budget and input freeze for authored-lineage V3 root adoption.

The public issuer accepts no caller intent, evidence, quote, or clock. It can
only consume W01's single current Owner-fenced read. Until W01 implements that
read, issuance holds before reserving budget. The signed original is still not
a Graph write permit; W01 rederives its contents in the final transaction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math
import sqlite3
import time

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .budget import get_budget_lease, reserve_budget
from .issuers import D11BudgetGrantIssuer, IssuerAuthorityDenied


ROOT_WORK_KIND_V3 = "d04.authored_root_adoption.v3"
_SIGN_KIND = "d11.d04-authored-root-freeze.v3"


class D11RootFreezeV3Hold(ValueError):
    """Current Owner, installed root assets, or signed D11 budget is unproved."""


def _text(value: object, label: str) -> None:
    if type(value) is not str or not value.strip():
        raise D11RootFreezeV3Hold(f"{label} is required")


def _sha(value: object, label: str) -> None:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise D11RootFreezeV3Hold(f"{label} needs a bare SHA-256 digest")


def _json_exact(encoded: object, label: str) -> object:
    if type(encoded) is not str:
        raise D11RootFreezeV3Hold(f"{label} must be canonical JSON")
    try:
        raw = json.loads(encoded)
        if canonical_serialize(raw) != encoded:
            raise ValueError("noncanonical")
        return raw
    except (TypeError, ValueError) as exc:
        raise D11RootFreezeV3Hold(f"{label} must be canonical JSON") from exc


@dataclass(frozen=True, slots=True)
class D11RootFreezeReadV3:
    """W01's exact read shape; creating this DTO cannot authenticate it."""

    namespace: NamespaceId
    operation_id: str
    owner_actor_id: str
    owner_session_id: str
    owner_session_binding_digest: str
    active_scheme_head: VersionedRef
    draft_head: VersionedRef
    draft_digest: str
    root_input_digest: str
    candidate_digest: str
    preset_digest: str
    asset_digest: str
    native_manifest_sha256: str
    native_sha256: str
    abi2_initial_box_digest: str
    abi2_readout_digest: str
    initial_transcript_digest: str
    output_projection_digest: str
    authored_write_set_json: str
    authored_write_set_digest: str
    graph_read_set_digest: str
    owner_fence_digest: str
    schema: str = "d11.d04_authored_root_freeze_read.v3"

    def __post_init__(self) -> None:
        if self.schema != "d11.d04_authored_root_freeze_read.v3":
            raise D11RootFreezeV3Hold("V2 root read cannot be used as V3")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("root freeze namespace must be typed")
        for name in ("operation_id", "owner_actor_id", "owner_session_id"):
            _text(getattr(self, name), name)
        if (type(self.active_scheme_head) is not VersionedRef
                or type(self.draft_head) is not VersionedRef):
            raise TypeError("root freeze requires exact D12 active scheme and draft heads")
        active_head_key = AtomKey.from_token(self.active_scheme_head.ref)
        if (active_head_key.type_name != "d12.active_scheme_head.v1"
                or active_head_key.name != "current"
                or AtomKey.from_token(self.draft_head.ref).type_name
                   != "d12.character_draft.v1"
                or any(NamespaceId.from_key(AtomKey.from_token(item.ref))
                       != self.namespace for item in (self.active_scheme_head, self.draft_head))
                or self.active_scheme_head.version < 1 or self.draft_head.version < 1):
            raise D11RootFreezeV3Hold("root freeze D12 active scheme/draft head type or scope differs")
        for name in (
            "owner_session_binding_digest", "draft_digest", "root_input_digest",
            "candidate_digest", "preset_digest", "asset_digest",
            "native_manifest_sha256", "native_sha256", "abi2_initial_box_digest",
            "abi2_readout_digest", "initial_transcript_digest",
            "output_projection_digest", "authored_write_set_digest",
            "graph_read_set_digest", "owner_fence_digest",
        ):
            _sha(getattr(self, name), name)
        writes = _json_exact(self.authored_write_set_json, "authored write set")
        if (type(writes) is not list or len(writes) < 6
                or any(type(item) is not list or len(item) != 3
                       or type(item[0]) is not str or type(item[1]) is not int
                       or item[1] != 1 or type(item[2]) is not dict for item in writes)
                or canonical_digest(tuple(tuple(item) for item in writes))
                   != self.authored_write_set_digest):
            raise D11RootFreezeV3Hold("complete authored rev1 write set differs")
        try:
            keys = tuple(AtomKey.from_token(item[0]) for item in writes)
        except (TypeError, ValueError) as exc:
            raise D11RootFreezeV3Hold("authored root write address differs") from exc
        kinds = tuple(key.type_name for key in keys)
        if (tuple(key.token for key in keys) != tuple(sorted({key.token for key in keys}))
                or any(NamespaceId.from_key(key) != self.namespace
                       or key.owner.kind != "persona" for key in keys)
                or kinds.count("d04.numeric_checkpoint.v2") != len(keys) // 2
                or kinds.count("d04.authored_feeling_state.v1") < 2
                or kinds.count("d04.authored_mood_state.v1") != 1
                or set(kinds) != {
                    "d04.numeric_checkpoint.v2", "d04.authored_feeling_state.v1",
                    "d04.authored_mood_state.v1",
                }):
            raise D11RootFreezeV3Hold("authored root writes have wrong V3 lineage")


@dataclass(frozen=True, slots=True)
class D11RootFreezeOriginalV3:
    namespace: NamespaceId
    operation_id: str
    parent_budget_lease_ref: str
    parent_budget_original_json: str
    parent_budget_original_digest: str
    grant_version: int
    grant_signature: str
    grant_digest: str
    grant_signature_digest: str
    quote_ceiling: tuple[tuple[str, int], ...]
    reserve_operation_id: str
    reserve_digest: str
    reserve_receipt_digest: str
    freeze_read_json: str
    freeze_read_digest: str
    frozen_at_utc: float
    original_digest: str
    schema: str = "d11.d04_authored_root_freeze_original.v3"

    def __post_init__(self) -> None:
        if self.schema != "d11.d04_authored_root_freeze_original.v3":
            raise D11RootFreezeV3Hold("V2 freeze original cannot be used as V3")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("root freeze namespace must be typed")
        for name in ("operation_id", "parent_budget_lease_ref", "reserve_operation_id",
                     "grant_signature"):
            _text(getattr(self, name), name)
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise D11RootFreezeV3Hold("grant version is invalid")
        for name in (
            "parent_budget_original_digest", "grant_digest", "grant_signature_digest",
            "reserve_digest", "reserve_receipt_digest", "freeze_read_digest",
            "original_digest",
        ):
            _sha(getattr(self, name), name)
        if self.grant_signature_digest != canonical_digest(self.grant_signature):
            raise D11RootFreezeV3Hold("grant signature digest differs")
        if (type(self.quote_ceiling) is not tuple or not self.quote_ceiling
                or tuple(name for name, _ in self.quote_ceiling)
                   != tuple(sorted({name for name, _ in self.quote_ceiling}))
                or any(type(amount) is not int or amount <= 0
                       for _, amount in self.quote_ceiling)):
            raise D11RootFreezeV3Hold("dedicated signed root quote ceiling is invalid")
        if type(self.frozen_at_utc) not in (int, float) or not math.isfinite(self.frozen_at_utc):
            raise D11RootFreezeV3Hold("freeze clock is invalid")
        if (canonical_digest(_json_exact(self.parent_budget_original_json, "budget lease"))
                != self.parent_budget_original_digest
                or canonical_digest(_json_exact(self.freeze_read_json, "W01 freeze read"))
                   != self.freeze_read_digest):
            raise D11RootFreezeV3Hold("frozen original content differs")


def _content(original: D11RootFreezeOriginalV3) -> dict:
    return {field.name: getattr(original, field.name) for field in fields(original)
            if field.name != "original_digest"}


def install_d11_root_freeze_v3(db: sqlite3.Connection) -> None:
    """Provision before the D11 issuer opens its transaction."""
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise D11RootFreezeV3Hold("D11 root schema installs outside transactions")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS runtime_d11_d04_root_freezes_v3 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            original_json TEXT NOT NULL, signature TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS runtime_d11_d04_root_freeze_no_update_v3
          BEFORE UPDATE ON runtime_d11_d04_root_freezes_v3
          BEGIN SELECT RAISE(ABORT, 'D11 root V3 freeze is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS runtime_d11_d04_root_freeze_no_delete_v3
          BEFORE DELETE ON runtime_d11_d04_root_freezes_v3
          BEGIN SELECT RAISE(ABORT, 'D11 root V3 freeze is immutable'); END;
    """)


def _transaction(db: sqlite3.Connection, issuer: D11BudgetGrantIssuer) -> None:
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or not isinstance(issuer, D11BudgetGrantIssuer)):
        raise D11RootFreezeV3Hold("signed D11 root freeze needs a caller-owned transaction")


def read_d11_root_freeze_v3(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str,
) -> D11RootFreezeOriginalV3 | None:
    """Read only a verified signed original and its historical budget reserve."""
    _transaction(db, issuer)
    row = db.execute(
        "SELECT original_json,signature FROM runtime_d11_d04_root_freezes_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        return None
    encoded, signature = row
    try:
        issuer._signer.verify(_SIGN_KIND, encoded, signature)
        raw = _json_exact(encoded, "signed freeze")
        if type(raw) is not dict or set(raw) != {
                field.name for field in fields(D11RootFreezeOriginalV3)}:
            raise ValueError("freeze fields differ")
        raw["namespace"] = NamespaceId(**raw["namespace"])
        raw["quote_ceiling"] = tuple(tuple(item) for item in raw["quote_ceiling"])
        original = D11RootFreezeOriginalV3(**raw)
        if (original.namespace != namespace or original.operation_id != operation_id
                or canonical_digest(_content(original)) != original.original_digest):
            raise ValueError("freeze identity differs")
        grant, grant_sig = issuer.signed_budget_grant_at_version(
            db, original.parent_budget_lease_ref, original.grant_version)
        if (grant_sig != original.grant_signature
                or canonical_digest(asdict(grant)) != original.grant_digest
                or grant.allowed_work_kinds != (ROOT_WORK_KIND_V3,)
                or tuple(sorted(grant.max_ceiling.items())) != original.quote_ceiling):
            raise ValueError("signed root grant differs")
        reservation = db.execute(
            "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            namespace.as_tuple + (original.reserve_operation_id,),
        ).fetchone()
        if (reservation is None or reservation[0] != original.reserve_digest
                or reservation[1] != original.parent_budget_lease_ref
                or canonical_digest(_json_exact(reservation[2], "reserve receipt"))
                   != original.reserve_receipt_digest):
            raise ValueError("root budget reservation differs")
        quote_row = db.execute(
            "SELECT digest,ceiling_json FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (original.parent_budget_lease_ref, original.reserve_operation_id),
        ).fetchone()
        quote = None if quote_row is None else _json_exact(quote_row[1], "reserve quote")
        if (quote_row is None or quote_row[0] != original.reserve_digest
                or type(quote) is not dict
                or tuple(sorted(quote.items()))
                   != original.quote_ceiling):
            raise ValueError("root signed quote differs from budget reservation")
        return original
    except (TypeError, ValueError, KeyError, IndexError, IssuerAuthorityDenied) as exc:
        raise D11RootFreezeV3Hold("D11 root V3 signature or original differs") from exc


def issue_d11_root_freeze_v3(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, coordinator: object, *,
    namespace: NamespaceId, operation_id: str, parent_budget_lease_ref: str,
) -> D11RootFreezeOriginalV3:
    """Freeze only W01's trusted current read and a dedicated signed grant."""
    _transaction(db, issuer)
    from ..graph_coordinator import GraphCoordinator

    reader = getattr(coordinator, "_read_d04_root_freeze_v3_for_d11", None)
    if (type(namespace) is not NamespaceId or type(coordinator) is not GraphCoordinator
            or not callable(reader)):
        raise D11RootFreezeV3Hold("trusted W01 Owner-fenced V3 root read unavailable")
    read = reader(db, namespace, operation_id)
    if (type(read) is not D11RootFreezeReadV3 or read.namespace != namespace
            or read.operation_id != operation_id):
        raise D11RootFreezeV3Hold("W01 V3 root freeze read identity differs")
    lease = get_budget_lease(db, parent_budget_lease_ref)
    grant = issuer.current_budget_grant(db, parent_budget_lease_ref)
    now_utc = time.time()
    if ((lease.bot_id, lease.persona_id) != namespace.as_tuple
            or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency)
               != (*namespace.as_tuple, parent_budget_lease_ref, lease.currency)
            or lease.state != "active"
            or grant.allowed_work_kinds != (ROOT_WORK_KIND_V3,)
            or not grant.max_ceiling or any(value <= 0 for value in grant.max_ceiling.values())
            or grant.valid_until_utc <= now_utc):
        raise D11RootFreezeV3Hold("dedicated signed D11 V3 root grant unavailable")
    _, grant_signature = issuer.signed_budget_grant_at_version(
        db, parent_budget_lease_ref, grant.version)
    read_json = canonical_serialize(asdict(read))
    read_digest = canonical_digest(_json_exact(read_json, "W01 V3 root read"))
    prior = read_d11_root_freeze_v3(
        db, issuer, namespace=namespace, operation_id=operation_id)
    if prior is not None:
        if (prior.freeze_read_digest != read_digest
                or prior.parent_budget_lease_ref != parent_budget_lease_ref):
            raise D11RootFreezeV3Hold("same V3 root operation has different frozen input")
        return prior
    budget_json = canonical_serialize(asdict(lease))
    budget_digest = canonical_digest(_json_exact(budget_json, "budget lease"))
    grant_digest = canonical_digest(asdict(grant))
    reserve_operation_id = "d11-root-v3-reserve:" + canonical_digest({
        "namespace": namespace.as_tuple, "operation_id": operation_id,
    })[:40]
    reserve_digest = canonical_digest({
        "schema": _SIGN_KIND, "read_digest": read_digest,
        "budget_digest": budget_digest, "grant_digest": grant_digest,
        "ceiling": tuple(sorted(grant.max_ceiling.items())),
    })
    receipt = reserve_budget(db, parent_budget_lease_ref, reserve_operation_id,
                             reserve_digest, grant.max_ceiling)
    payload = dict(
        namespace=namespace, operation_id=operation_id,
        parent_budget_lease_ref=parent_budget_lease_ref,
        parent_budget_original_json=budget_json,
        parent_budget_original_digest=budget_digest,
        grant_version=grant.version, grant_signature=grant_signature,
        grant_digest=grant_digest,
        grant_signature_digest=canonical_digest(grant_signature),
        quote_ceiling=tuple(sorted(grant.max_ceiling.items())),
        reserve_operation_id=reserve_operation_id, reserve_digest=reserve_digest,
        reserve_receipt_digest=canonical_digest(asdict(receipt)),
        freeze_read_json=read_json, freeze_read_digest=read_digest,
        frozen_at_utc=now_utc, schema="d11.d04_authored_root_freeze_original.v3",
    )
    original = D11RootFreezeOriginalV3(**payload, original_digest=canonical_digest(payload))
    encoded = canonical_serialize(asdict(original))
    signature = issuer._signer.sign(_SIGN_KIND, encoded)
    db.execute("INSERT INTO runtime_d11_d04_root_freezes_v3 VALUES(?,?,?,?,?)",
               (*namespace.as_tuple, operation_id, encoded, signature))
    if read_d11_root_freeze_v3(
            db, issuer, namespace=namespace, operation_id=operation_id) != original:
        raise D11RootFreezeV3Hold("signed V3 freeze did not round-trip")
    return original


__all__ = [
    "ROOT_WORK_KIND_V3", "D11RootFreezeV3Hold", "D11RootFreezeReadV3",
    "D11RootFreezeOriginalV3", "install_d11_root_freeze_v3",
    "issue_d11_root_freeze_v3", "read_d11_root_freeze_v3",
]
