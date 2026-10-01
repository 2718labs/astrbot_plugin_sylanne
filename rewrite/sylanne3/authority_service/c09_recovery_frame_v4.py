"""Versioned source seal/pin and suffix frame; legacy V3 originals unchanged."""
from __future__ import annotations

from dataclasses import dataclass, fields
import json
from types import SimpleNamespace

from ..runtime_contracts import canonical_digest
from ..runtime.c09_storage_rebase_contract_v1 import (
    SanitizedExecutionFactV4, SanitizedD02FactV4, SanitizedD11FactV4,
    SanitizedUnknownFactV4, SanitizedGraphFactV4, _id, _digest, _ordered,
)
from .contract import AuthorityUnavailable


@dataclass(frozen=True, slots=True)
class C09ExecutionSourceSealV4:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    prior_prefix_digest: str | None
    suffix_row_commitments: tuple[str, ...]
    accepted_receipt_digest: str
    seal_digest: str
    schema: str = "sylanne3.c09.execution_source_seal.v4"

    def __post_init__(self):
        for name in ("authority_id", "installation_id", "namespace", "operation_id", "execution_journal_id"):
            _id(getattr(self,name),name)
        if type(self.execution_seq) is not int or self.execution_seq < 0 or len(self.suffix_row_commitments) != self.execution_seq:
            raise ValueError("C09 source suffix sequence differs")
        if self.execution_seq == 0:
            if self.execution_digest != "genesis":
                raise ValueError("C09 empty verified suffix head differs")
        else:
            if not self.execution_digest.startswith("sha256:"):
                raise ValueError("C09 suffix digest syntax differs")
            _digest(self.execution_digest[7:], "suffix digest")
        if self.prior_prefix_digest is not None:
            _digest(self.prior_prefix_digest,"prior prefix")
        for value in self.suffix_row_commitments:
            _digest(value,"row commitment")
        _digest(self.accepted_receipt_digest,"accepted receipt")
        if self.seal_digest != canonical_digest(tuple(getattr(self,f.name) for f in fields(self) if f.name != "seal_digest")):
            raise ValueError("C09 source seal digest differs")


@dataclass(frozen=True, slots=True)
class C09ExecutionSourcePinV4:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    seal_digest: str
    old_journal_id: str
    old_seq: int
    old_digest: str
    verifier_commitment: str
    facts_digest: str
    prior_prefix_digest: str | None
    pin_digest: str
    schema: str = "sylanne3.c09.execution_source_pin.v4"

    def __post_init__(self):
        for name in ("authority_id", "installation_id", "namespace", "operation_id", "old_journal_id"):
            _id(getattr(self,name),name)
        if type(self.old_seq) is not int or self.old_seq < 0 or (self.old_seq == 0 and self.old_digest != "genesis"):
            raise ValueError("C09 source pin empty head differs")
        if self.old_seq:
            if not self.old_digest.startswith("sha256:"):
                raise ValueError("C09 source pin suffix syntax differs")
            _digest(self.old_digest[7:],"old suffix digest")
        for name in ("seal_digest","verifier_commitment","facts_digest"):
            _digest(getattr(self,name),name)
        if self.prior_prefix_digest is not None:
            _digest(self.prior_prefix_digest,"prior prefix")
        if self.pin_digest != canonical_digest(tuple(getattr(self,f.name) for f in fields(self) if f.name != "pin_digest")):
            raise ValueError("C09 source pin digest differs")


@dataclass(frozen=True, slots=True)
class C09RecoveryFactFrameV4:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    old_journal_id: str
    old_seq: int
    old_chain_head_digest: str
    prior_fact_frame_digests: tuple[str, ...]
    verifier_commitment: str
    executions: tuple[SanitizedExecutionFactV4, ...]
    d02_facts: tuple[SanitizedD02FactV4, ...]
    d11_facts: tuple[SanitizedD11FactV4, ...]
    unknown_facts: tuple[SanitizedUnknownFactV4, ...]
    graph_facts: tuple[SanitizedGraphFactV4, ...]
    facts_digest: str
    schema: str = "sylanne3.c09.recovery_fact_frame.v4"

    def __post_init__(self):
        for name in ("authority_id","installation_id","namespace","operation_id","old_journal_id"):
            _id(getattr(self,name),name)
        if type(self.old_seq) is not int or self.old_seq < 0 or (self.old_seq == 0 and self.old_chain_head_digest != "genesis"):
            raise ValueError("C09 fact frame suffix head differs")
        if self.old_seq:
            if not self.old_chain_head_digest.startswith("sha256:"):
                raise ValueError("C09 fact frame suffix syntax differs")
            _digest(self.old_chain_head_digest[7:],"old suffix digest")
        for value in self.prior_fact_frame_digests:
            _digest(value,"prior fact frame")
        for name, cls, key in (("executions",SanitizedExecutionFactV4,lambda x:x.execution_id),
                ("d02_facts",SanitizedD02FactV4,lambda x:x.quote_id),
                ("d11_facts",SanitizedD11FactV4,lambda x:x.settlement_id),
                ("unknown_facts",SanitizedUnknownFactV4,lambda x:x.execution_id),
                ("graph_facts",SanitizedGraphFactV4,lambda x:x.operation_id)):
            _ordered(getattr(self,name),cls,name,key)
        if {f.execution_id for f in self.executions if f.status == "unknown"} != {f.execution_id for f in self.unknown_facts}:
            raise ValueError("C09 suffix unknown facts incomplete")
        if self.facts_digest != canonical_digest(tuple(getattr(self,f.name) for f in fields(self) if f.name != "facts_digest")):
            raise ValueError("C09 fact frame digest differs")


def make_source_seal_v4(**body):
    body["schema"] = "sylanne3.c09.execution_source_seal.v4"
    ordered = tuple(body[f.name] for f in fields(C09ExecutionSourceSealV4) if f.name != "seal_digest")
    return C09ExecutionSourceSealV4(**body,seal_digest=canonical_digest(ordered))


def make_fact_frame_v4(**body):
    body["schema"] = "sylanne3.c09.recovery_fact_frame.v4"
    ordered = tuple(body[f.name] for f in fields(C09RecoveryFactFrameV4) if f.name != "facts_digest")
    return C09RecoveryFactFrameV4(**body,facts_digest=canonical_digest(ordered))


def make_source_pin_v4(*,seal,facts):
    body = dict(authority_id=seal.authority_id,installation_id=seal.installation_id,
        namespace=seal.namespace,operation_id=seal.operation_id,seal_digest=seal.seal_digest,
        old_journal_id=seal.execution_journal_id,old_seq=seal.execution_seq,
        old_digest=seal.execution_digest,verifier_commitment=facts.verifier_commitment,
        facts_digest=facts.facts_digest,prior_prefix_digest=seal.prior_prefix_digest,
        schema="sylanne3.c09.execution_source_pin.v4")
    ordered = tuple(body[f.name] for f in fields(C09ExecutionSourcePinV4) if f.name != "pin_digest")
    return C09ExecutionSourcePinV4(**body,pin_digest=canonical_digest(ordered))
