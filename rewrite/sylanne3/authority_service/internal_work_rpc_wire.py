"""Exact JSON shapes for the installed C04 terminal reread RPC."""

from __future__ import annotations

from dataclasses import asdict, fields
import re

from .contract import JournalHead
from .internal_work_contract import (
    InternalWorkBindingV1, InternalWorkClaimV1, InternalWorkTerminalProofV1,
    InternalWorkTerminalV1, InternalWorkTerminalV2,
)
from .internal_work_service import (
    AuthorityInternalWorkVerifiedReceiptV1, InternalWorkJournalAppendV1,
    InternalWorkJournalInspectionV1,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _record(raw: object, cls: type) -> dict:
    if type(raw) is not dict or set(raw) != {item.name for item in fields(cls)}:
        raise ValueError("C04 RPC fields differ")
    return raw


def to_wire(value: object) -> dict:
    if type(value) not in (InternalWorkBindingV1, InternalWorkJournalInspectionV1,
                           InternalWorkTerminalProofV1,
                           AuthorityInternalWorkVerifiedReceiptV1):
        raise TypeError("typed C04 RPC fact required")
    if type(value) is InternalWorkTerminalProofV1 and type(value.terminal) is not InternalWorkTerminalV2:
        raise ValueError("installed C04 V2 terminal required")
    return asdict(value)


def from_wire(raw: object, cls: type):
    try:
        value = _record(raw, cls)
        if cls is InternalWorkBindingV1:
            decoded = cls(**value)
        elif cls is InternalWorkJournalInspectionV1:
            terminal_raw = value["terminal"]
            terminal = None
            if terminal_raw is not None:
                terminal_type = (InternalWorkTerminalV2
                                 if type(terminal_raw) is dict and
                                 terminal_raw.get("schema") ==
                                 "sylanne3.internal_work.terminal.v2"
                                 else InternalWorkTerminalV1)
                terminal = terminal_type(**_record(terminal_raw, terminal_type))
            decoded = cls(
                cls_binding := InternalWorkBindingV1(**_record(
                    value["binding"], InternalWorkBindingV1)),
                (InternalWorkClaimV1(**_record(value["claim"], InternalWorkClaimV1))
                 if value["claim"] is not None else None),
                terminal,
                (InternalWorkJournalAppendV1(**_record(
                    value["claim_append"], InternalWorkJournalAppendV1))
                 if value["claim_append"] is not None else None),
                (InternalWorkJournalAppendV1(**_record(
                    value["terminal_append"], InternalWorkJournalAppendV1))
                 if value["terminal_append"] is not None else None),
                JournalHead(**_record(value["verified_head"], JournalHead)),
            )
            if (decoded.claim is not None and
                    decoded.claim.binding_digest != cls_binding.binding_digest):
                raise ValueError("C04 inspection binding differs")
        elif cls is InternalWorkTerminalProofV1:
            decoded = cls(
                InternalWorkBindingV1(**_record(value["binding"], InternalWorkBindingV1)),
                InternalWorkClaimV1(**_record(value["claim"], InternalWorkClaimV1)),
                InternalWorkTerminalV2(**_record(value["terminal"], InternalWorkTerminalV2)),
                value["claim_receipt_ref"], value["claim_receipt_digest"],
                value["terminal_receipt_ref"], value["terminal_receipt_digest"],
                JournalHead(**_record(value["journal_head"], JournalHead)),
                value["schema"],
            )
        elif cls is AuthorityInternalWorkVerifiedReceiptV1:
            decoded = cls(**{**value,
                             "journal_head": JournalHead(**_record(
                                 value["journal_head"], JournalHead))})
            if (any(type(getattr(decoded, name)) is not str or
                    _SHA256.fullmatch(getattr(decoded, name)) is None
                    for name in ("proof_digest", "input_digest",
                                 "resource_quote_digest", "terminal_receipt_digest"))
                    or any(type(getattr(decoded, name)) is not str or
                           not getattr(decoded, name)
                           for name in ("namespace", "activity_id", "operation_id",
                                        "execution_id", "resource_quote_ref",
                                        "terminal_receipt_ref"))
                    or type(decoded.resource_quote_version) is not int
                    or decoded.resource_quote_version < 0
                    or type(decoded.terminal_sequence) is not int
                    or not 2 <= decoded.terminal_sequence <= decoded.journal_head.seq
                    or decoded.status not in {"completed", "failed"}
                    or type(decoded.actual_cpu_ms) is not int
                    or decoded.actual_cpu_ms < 0
                    or type(decoded.component_completed) is not bool
                    or (decoded.status == "failed" and decoded.component_completed)):
                raise ValueError("C04 verified receipt is malformed")
        else:
            raise TypeError("unsupported C04 RPC fact")
        if asdict(decoded) != value:
            raise ValueError("C04 RPC canonical fact differs")
        return decoded
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("C04 RPC fact is invalid") from exc


__all__ = ("to_wire", "from_wire")
