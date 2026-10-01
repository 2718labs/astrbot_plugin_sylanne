"""Authority-owned D07 interval originals beside the once-only model ledger."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import time

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable

TABLE = "authority_d07_model_timings_v1"


@dataclass(frozen=True, slots=True)
class D07ModelTimingOriginalV1:
    call_id: str
    admission_id: str
    request_digest: str
    binding_digest: str
    started_at: float
    ended_at: float
    terminal_digest: str
    schema: str = "d07.authority-model-timing.v1"

    def __post_init__(self):
        if (self.schema != "d07.authority-model-timing.v1"
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in (self.started_at, self.ended_at))
                or self.started_at < 0 or self.ended_at < self.started_at):
            raise ValueError("D07 actual bounded Authority interval required")
        from .contract import identifier
        identifier(self.call_id, "call_id")
        for value in (self.admission_id, self.request_digest, self.binding_digest, self.terminal_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("D07 interval original identity differs")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def install_d07_model_timing_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        call_id TEXT PRIMARY KEY, admission_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL, binding_digest TEXT NOT NULL,
        started_at REAL NOT NULL, ended_at REAL, terminal_digest TEXT,
        CHECK((ended_at IS NULL AND terminal_digest IS NULL) OR
            (ended_at IS NOT NULL AND terminal_digest IS NOT NULL AND ended_at>=started_at)),
        FOREIGN KEY(call_id) REFERENCES authority_model_egress_v1(call_id))""")


def record_d07_model_start_locked_v1(db, intent, admission, *, now_utc=None):
    if not db.in_transaction or admission is None:
        raise AuthorityUnavailable("D07 start requires actual Authority admission transaction")
    now = time.time() if now_utc is None else now_utc
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        raise AuthorityUnavailable("D07 trusted Authority clock unavailable")
    db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,NULL,NULL)",
        (intent.call_id, admission.admission_id, intent.request_digest, intent.binding_digest, now))


def record_d07_model_end_locked_v1(db, intent, receipt, *, now_utc=None):
    if not db.in_transaction:
        raise AuthorityUnavailable("D07 completion requires actual Authority terminal transaction")
    row = db.execute(f"SELECT admission_id,request_digest,binding_digest,started_at,ended_at,terminal_digest FROM {TABLE} WHERE call_id=?",
        (intent.call_id,)).fetchone()
    if row is None:
        return  # Another workflow has no D07 interval and is never converted.
    terminal_digest = canonical_digest(asdict(receipt))
    if row[:3] != (receipt.admission_id, intent.request_digest, intent.binding_digest):
        raise AuthorityUnavailable("D07 independent interval differs from actual model original")
    if row[4] is not None:
        if row[5] != terminal_digest:
            raise AuthorityUnavailable("D07 interval completion conflicts with original terminal")
        return
    now = time.time() if now_utc is None else now_utc
    if type(now) not in (int, float) or not math.isfinite(now) or now < row[3]:
        raise AuthorityUnavailable("D07 Authority clock moved backward; interval stays unknown")
    db.execute(f"UPDATE {TABLE} SET ended_at=?,terminal_digest=? WHERE call_id=? AND ended_at IS NULL",
        (now, terminal_digest, intent.call_id))
    if db.execute("SELECT changes()").fetchone() != (1,):
        raise AuthorityUnavailable("D07 interval terminal CAS changed")


def read_d07_model_timing_locked_v1(db, intent, receipt):
    row = db.execute(f"SELECT call_id,admission_id,request_digest,binding_digest,started_at,ended_at,terminal_digest FROM {TABLE} WHERE call_id=?",
        (intent.call_id,)).fetchone()
    if row is None or row[5] is None:
        raise AuthorityUnavailable("D07 actual original interval is unresolved")
    result = D07ModelTimingOriginalV1(*row)
    if (result.admission_id != receipt.admission_id or result.request_digest != intent.request_digest
            or result.binding_digest != intent.binding_digest or result.terminal_digest != canonical_digest(asdict(receipt))):
        raise AuthorityUnavailable("D07 interval/terminal original identity differs")
    return result
