"""D11 signed, durable freeze for one authored D04 root attempt.

Only a real GraphCoordinator Owner-fenced read may supply the freeze input.
The signed D11 original is budget and input evidence; W01 must still rederive
the complete current root in its final graph transaction before adoption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math
import sqlite3
import time

from ..domains.d12.authored_root import D12AuthoredRootIntentV2
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .budget import BudgetLease, get_budget_lease, reserve_budget
from .issuers import D11BudgetGrantIssuer, IssuerAuthorityDenied


ROOT_WORK_KIND_V2 = "d04.authored_root_adoption.v2"
_SIGN_KIND = "d11.d04-authored-root-freeze.v2"


class D11RootFreezeHold(ValueError):
    """No current signed budget authority or trusted W01 freeze read exists."""


def _sha(value: object, name: str) -> None:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise D11RootFreezeHold(f"{name} needs a bare SHA-256 digest")


@dataclass(frozen=True, slots=True)
class D11RootFreezeReadV2:
    """Result shape of a single current, Owner-fenced W01 read and pure replay.

    Instantiating this DTO does not authenticate it. The D11 issuer only accepts
    the value returned by GraphCoordinator's private trusted read method.
    """

    intent: D12AuthoredRootIntentV2
    d01_head: VersionedRef
    draft_head: VersionedRef
    owner_session_binding_digest: str
    graph_read_set_digest: str
    initial_transcript_digest: str
    output_projection_digest: str
    output_write_set_digest: str
    native_manifest_sha256: str
    native_sha256: str
    fence_binding_digest: str

    def __post_init__(self) -> None:
        if type(self.intent) is not D12AuthoredRootIntentV2:
            raise TypeError("W01 freeze needs a current D12 root intent")
        if (self.intent.status != "hold_for_d11_root_adoption"
                or type(self.d01_head) is not VersionedRef
                or type(self.draft_head) is not VersionedRef
                or (self.d01_head.ref, self.d01_head.version)
                   != (self.intent.active_head_ref, self.intent.active_head_revision)
                or (self.draft_head.ref, self.draft_head.version)
                   != (self.intent.draft_ref, self.intent.draft_revision)
                or self.intent.input_digest != canonical_digest(self.intent.root_input)):
            raise D11RootFreezeHold("W01 root intent and exact heads differ")
        for name in (
            "owner_session_binding_digest", "graph_read_set_digest",
            "initial_transcript_digest", "output_projection_digest",
            "output_write_set_digest", "native_manifest_sha256",
            "native_sha256", "fence_binding_digest",
        ):
            _sha(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class D11RootAdoptionFreezeOriginalV2:
    namespace: NamespaceId
    operation_id: str
    parent_budget_lease_ref: str
    parent_budget_original_json: str
    parent_budget_original_digest: str
    grant_version: int
    grant_signature: str
    grant_digest: str
    quote_ceiling: tuple[tuple[str, int], ...]
    reserve_operation_id: str
    reserve_digest: str
    reserve_receipt_digest: str
    freeze_read_json: str
    freeze_read_digest: str
    frozen_at_utc: float
    original_digest: str
    schema: str = "d11.d04_authored_root_freeze_original.v2"

    def __post_init__(self) -> None:
        if self.schema != "d11.d04_authored_root_freeze_original.v2":
            raise D11RootFreezeHold("unknown D11 root freeze schema")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("freeze namespace must be typed")
        for name in ("operation_id", "parent_budget_lease_ref", "reserve_operation_id"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise D11RootFreezeHold(f"{name} is required")
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise D11RootFreezeHold("grant version is invalid")
        for name in ("parent_budget_original_digest", "grant_digest", "reserve_digest",
                     "reserve_receipt_digest", "freeze_read_digest", "original_digest"):
            _sha(getattr(self, name), name)
        if type(self.grant_signature) is not str or not self.grant_signature:
            raise D11RootFreezeHold("signed grant is required")
        if (type(self.quote_ceiling) is not tuple or not self.quote_ceiling
                or tuple(name for name, _ in self.quote_ceiling)
                   != tuple(sorted({name for name, _ in self.quote_ceiling}))
                or any(type(amount) is not int or amount <= 0
                       for _, amount in self.quote_ceiling)):
            raise D11RootFreezeHold("root quote ceiling must be signed and positive")
        if type(self.frozen_at_utc) not in (int, float) or not math.isfinite(self.frozen_at_utc):
            raise D11RootFreezeHold("freeze clock is invalid")
        for encoded, digest, label in (
            (self.parent_budget_original_json, self.parent_budget_original_digest, "lease"),
            (self.freeze_read_json, self.freeze_read_digest, "read"),
        ):
            try:
                if canonical_serialize(json.loads(encoded)) != encoded:
                    raise ValueError("noncanonical")
            except (TypeError, ValueError) as exc:
                raise D11RootFreezeHold(f"{label} original is malformed") from exc
            if canonical_digest(json.loads(encoded)) != digest:
                raise D11RootFreezeHold(f"{label} original digest differs")


def _content(original: D11RootAdoptionFreezeOriginalV2) -> dict:
    return {field.name: getattr(original, field.name) for field in fields(original)
            if field.name != "original_digest"}


def install_d11_root_freeze_v2(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise D11RootFreezeHold("D11 root freeze schema installs outside transactions")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS runtime_d11_d04_root_freezes_v2 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            original_json TEXT NOT NULL, signature TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS runtime_d11_d04_root_freeze_no_update_v2
          BEFORE UPDATE ON runtime_d11_d04_root_freezes_v2
          BEGIN SELECT RAISE(ABORT, 'D11 root freeze is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS runtime_d11_d04_root_freeze_no_delete_v2
          BEFORE DELETE ON runtime_d11_d04_root_freezes_v2
          BEGIN SELECT RAISE(ABORT, 'D11 root freeze is immutable'); END;
    """)


def _transaction(db: sqlite3.Connection, issuer: D11BudgetGrantIssuer) -> None:
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or not isinstance(issuer, D11BudgetGrantIssuer)):
        raise D11RootFreezeHold("D11 signed root freeze needs an issuer transaction")


def read_d11_root_freeze_v2(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str,
) -> D11RootAdoptionFreezeOriginalV2 | None:
    """Verify a persisted D11 signature, grant and reserve receipt, even on retry."""
    _transaction(db, issuer)
    row = db.execute(
        "SELECT original_json,signature FROM runtime_d11_d04_root_freezes_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        return None
    encoded, signature = row
    try:
        issuer._signer.verify(_SIGN_KIND, encoded, signature)
        raw = json.loads(encoded)
        if (type(raw) is not dict or canonical_serialize(raw) != encoded
                or set(raw) != {field.name for field in fields(D11RootAdoptionFreezeOriginalV2)}):
            raise ValueError("original fields differ")
        raw["namespace"] = NamespaceId(**raw["namespace"])
        raw["quote_ceiling"] = tuple(tuple(item) for item in raw["quote_ceiling"])
        original = D11RootAdoptionFreezeOriginalV2(**raw)
        if (original.namespace != namespace or original.operation_id != operation_id
                or canonical_digest(_content(original)) != original.original_digest):
            raise ValueError("original identity differs")
        grant, grant_signature = issuer.signed_budget_grant_at_version(
            db, original.parent_budget_lease_ref, original.grant_version)
        if (grant_signature != original.grant_signature
                or canonical_digest(asdict(grant)) != original.grant_digest
                or ROOT_WORK_KIND_V2 not in grant.allowed_work_kinds
                or tuple(sorted(grant.max_ceiling.items())) != original.quote_ceiling):
            raise ValueError("signed root budget grant differs")
        budget_row = db.execute(
            "SELECT digest,receipt_json FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            namespace.as_tuple + (original.reserve_operation_id,),
        ).fetchone()
        if (budget_row is None or budget_row[0] != original.reserve_digest
                or canonical_digest(json.loads(budget_row[1]))
                   != original.reserve_receipt_digest):
            raise ValueError("root budget reservation original differs")
        return original
    except (TypeError, ValueError, KeyError, IndexError, IssuerAuthorityDenied) as exc:
        raise D11RootFreezeHold("D11 root freeze signature or original differs") from exc


def issue_d11_root_freeze_v2(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, coordinator: object, *,
    namespace: NamespaceId, operation_id: str, parent_budget_lease_ref: str,
) -> D11RootAdoptionFreezeOriginalV2:
    """V2 Feeling/Mood root is permanently HOLD after authored-lineage V3."""
    raise D11RootFreezeHold(
        "V2 root Feeling/Mood lineage is superseded; use authored-lineage V3"
    )

__all__ = [
    "ROOT_WORK_KIND_V2", "D11RootFreezeHold", "D11RootFreezeReadV2",
    "D11RootAdoptionFreezeOriginalV2", "install_d11_root_freeze_v2",
    "issue_d11_root_freeze_v2", "read_d11_root_freeze_v2",
]
