"""D12 creator scheme command boundary, pending a trusted W01 implementation.

This module owns no graph or experiment state. The installed port must obtain
creator authority and current draft/head values inside W01's read fence, route
each field to its owning domain compiler, isolate preview execution, and make
adoption a single current graph transaction. No caller-supplied preview or
domain receipt is accepted by the public issuer methods.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
from typing import Callable, Protocol, TypeVar

from ...graph_types import AtomKey
from ...runtime_contracts import AuthorityContext, NamespaceId, canonical_digest, canonical_serialize
from .types import CharacterDraft, active_scheme_head_key, character_draft_key


class D12SchemeHold(ValueError):
    """A creator scheme command lacks a current or trusted prerequisite."""

    def __init__(self, message: str, *, code: str = "scheme_hold",
                 diagnostics: tuple[D12SchemeDiagnosticV1, ...] = ()) -> None:
        super().__init__(message)
        self.code = code
        self.diagnostics = diagnostics


_T = TypeVar("_T")
_SCHEME_DOMAINS = frozenset(f"d{index:02d}" for index in range(1, 11))
_FIELD_PATH = re.compile(r"d(?:0[1-9]|10)\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\Z")


@dataclass(frozen=True, slots=True)
class D12SchemeDiagnosticV1:
    field_path: str
    code: str
    message: str

    def __post_init__(self) -> None:
        if (type(self.field_path) is not str or not self.field_path
                or type(self.code) is not str or not self.code
                or type(self.message) is not str or not self.message):
            raise ValueError("scheme diagnostic requires field, code and message")


@dataclass(frozen=True, slots=True)
class D12DomainCompileRejectionV1:
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    diagnostics: tuple[D12SchemeDiagnosticV1, ...]
    status: str = "domain_rejected_candidate"


@dataclass(frozen=True, slots=True)
class D12DraftUpdateDecisionV1:
    """A read-only CAS proposal; W01 owns any graph write or retry receipt."""

    operation_id: str
    draft_ref: str
    expected_revision: int
    expected_digest: str
    current_revision: int
    current_digest: str
    proposed_digest: str
    creator_changed_fields: tuple[str, ...]
    concurrent_changed_fields: tuple[str, ...]
    conflicting_fields: tuple[str, ...]
    proposed_draft: CharacterDraft | None
    status: str


def plan_creator_draft_update_v1(
        frame: D12CurrentCreatorDraftV1, authority: AuthorityContext, *,
        operation_id: str, base_draft: CharacterDraft,
        proposed_draft: CharacterDraft) -> D12DraftUpdateDecisionV1:
    """Diagnose a three-way draft edit without committing or auto-merging it.

    Repeated operations must query W01's durable operation receipt. A matching
    proposed value after another writer won is still stale here.
    """
    D12SchemeCommandIssuer._authority(authority)
    current_digest = D12SchemeCommandIssuer._current(frame, authority)
    if (type(operation_id) is not str or not operation_id
            or type(base_draft) is not CharacterDraft
            or type(proposed_draft) is not CharacterDraft
            or base_draft.scope != frame.draft.scope
            or proposed_draft.scope != frame.draft.scope
            or proposed_draft.revision != base_draft.revision + 1):
        raise D12SchemeHold("draft edit has no valid base or next revision")

    def changed(left: CharacterDraft, right: CharacterDraft) -> tuple[str, ...]:
        names = set(left.fields) | set(right.fields)
        return tuple(sorted(name for name in names if (
            name in left.fields, left.fields.get(name), left.field_sources.get(name),
        ) != (
            name in right.fields, right.fields.get(name), right.field_sources.get(name),
        )))

    creator = changed(base_draft, proposed_draft)
    if not creator:
        raise D12SchemeHold("draft edit contains no changed fields")
    concurrent = changed(base_draft, frame.draft)
    stale = (base_draft.revision != frame.draft_revision
             or canonical_digest(base_draft) != current_digest)
    return D12DraftUpdateDecisionV1(
        operation_id, frame.draft_ref, base_draft.revision,
        canonical_digest(base_draft), frame.draft_revision, current_digest,
        canonical_digest(proposed_draft), creator, concurrent,
        tuple(sorted(set(creator) & set(concurrent))) if stale else (),
        None if stale else proposed_draft,
        "stale_requires_merge" if stale else "candidate_requires_w01_cas",
    )


@dataclass(frozen=True, slots=True)
class D12CurrentCreatorDraftV1:
    namespace: NamespaceId
    draft_ref: str
    draft_revision: int
    draft: CharacterDraft
    active_head_ref: str
    active_head_revision: int
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    creator_authorized: bool


@dataclass(frozen=True, slots=True)
class D12DomainCompileReceiptV1:
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    candidate_ref: str
    proposal_schema_hash: str
    status: str = "domain_compiled_candidate"


@dataclass(frozen=True, slots=True)
class D12CompiledSchemeV1:
    namespace: NamespaceId
    draft_ref: str
    draft_revision: int
    draft_digest: str
    active_head_ref: str
    active_head_revision: int
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    domain_receipts: tuple[D12DomainCompileReceiptV1, ...]
    compiled_digest: str
    issuer_seal: str
    status: str = "compiled_candidate_requires_current_adoption"


@dataclass(frozen=True, slots=True)
class D12IsolatedPreviewV1:
    compiled_digest: str
    sandbox_namespace: NamespaceId
    source_snapshot_digest: str
    production_revision_before: int
    production_revision_after: int
    external_effect_refs: tuple[str, ...]
    formal_contribution_refs: tuple[str, ...]
    production_write_refs: tuple[str, ...]
    actual_cost_receipt_ref: str
    status: str = "isolated_preview_only"


@dataclass(frozen=True, slots=True)
class D12PreviewCertificateV1:
    compiled_digest: str
    sandbox_namespace: NamespaceId
    actual_cost_receipt_ref: str
    issuer_seal: str
    status: str = "preview_candidate_no_adoption_authority"


@dataclass(frozen=True, slots=True)
class D12SchemeAdoptionIntentV1:
    operation_id: str
    namespace: NamespaceId
    compiled_digest: str
    expected_draft_ref: str
    expected_draft_revision: int
    expected_active_head_ref: str
    expected_active_head_revision: int
    expected_graph_revision: int
    expected_access_epoch: int
    expected_delete_epoch: int
    preview_seal: str
    issuer_seal: str
    status: str = "hold_for_w01_atomic_adoption"


@dataclass(frozen=True, slots=True)
class D12SchemeAdoptionReceiptV1:
    operation_id: str
    namespace: NamespaceId
    compiled_digest: str
    previous_head_ref: str
    previous_head_revision: int
    active_head_ref: str
    active_head_revision: int
    graph_revision: int
    status: str = "coordinator_committed_scheme"


@dataclass(frozen=True, slots=True)
class D12RollbackDraftIntentV1:
    namespace: NamespaceId
    historical_plan_ref: str
    expected_active_head_ref: str
    expected_active_head_revision: int
    status: str = "hold_for_new_administrative_draft_and_recompile"


class D12CreatorDraftReadPort(Protocol):
    def with_current_creator_draft_v1(
        self, authority: AuthorityContext, lease: object, *, draft_ref: str,
        required_capability: str,
        project: Callable[[D12CurrentCreatorDraftV1], _T],
    ) -> _T: ...


class D12TrustedSchemePort(D12CreatorDraftReadPort, Protocol):
    def compile_domain_scheme_v1(
        self, *, domain: str, fields: tuple[tuple[str, object, str], ...],
        field_input_digest: str,
    ) -> D12DomainCompileReceiptV1 | D12DomainCompileRejectionV1: ...

    def preview_isolated_scheme_v1(
        self, authority: AuthorityContext, lease: object, *,
        compiled: D12CompiledSchemeV1,
    ) -> D12IsolatedPreviewV1: ...

    def record_compilation_original_v1(
        self, authority: AuthorityContext, lease: object, *,
        compiled: D12CompiledSchemeV1,
    ) -> None: ...

    def record_preview_original_v1(
        self, authority: AuthorityContext, lease: object, *,
        compiled: D12CompiledSchemeV1, result: D12IsolatedPreviewV1,
        certificate: D12PreviewCertificateV1,
    ) -> None: ...

    def read_compilation_original_v1(
        self, authority: AuthorityContext, lease: object, *,
        compiled_digest: str,
    ) -> D12CompiledSchemeV1 | None: ...

    def read_preview_original_v1(
        self, authority: AuthorityContext, lease: object, *,
        preview_seal: str,
    ) -> D12PreviewCertificateV1 | None: ...

    def commit_current_scheme_v1(
        self, authority: AuthorityContext, lease: object, *,
        intent: D12SchemeAdoptionIntentV1,
    ) -> D12SchemeAdoptionReceiptV1: ...


def compiled_scheme_digest_v1(compiled: D12CompiledSchemeV1) -> str:
    """Recompute the candidate basis independently of the process-local seal.

    W01 must also compare this basis with current graph atoms and read epochs
    inside its commit transaction; a matching digest alone grants no adoption.
    """
    if type(compiled) is not D12CompiledSchemeV1:
        raise TypeError("compiled scheme is required")
    return canonical_digest((
        compiled.namespace, compiled.draft_ref, compiled.draft_revision,
        compiled.draft_digest, compiled.active_head_ref,
        compiled.active_head_revision, compiled.graph_revision,
        compiled.access_epoch, compiled.delete_epoch, compiled.domain_receipts,
    ))

class D12SchemeCommandIssuer:
    """Private installed issuer; W01 must implement the authority port."""

    def __init__(self, port: D12CreatorDraftReadPort) -> None:
        if not callable(getattr(port, "with_current_creator_draft_v1", None)):
            raise D12SchemeHold("trusted W01 creator scheme port is unavailable")
        self._port = port
        self._key = secrets.token_bytes(32)

    def _seal(self, value: object) -> str:
        return hmac.new(self._key, canonical_serialize(
            replace(value, issuer_seal=""),
        ).encode("utf-8"), hashlib.sha256).hexdigest()

    def _verified(self, value: object) -> bool:
        try:
            seal = value.issuer_seal
            return type(seal) is str and hmac.compare_digest(seal, self._seal(value))
        except (AttributeError, TypeError, ValueError):
            return False

    def _verified_compilation_original(
            self, authority: AuthorityContext, lease: object,
            compiled: D12CompiledSchemeV1) -> bool:
        if (type(compiled) is not D12CompiledSchemeV1
                or compiled.namespace != authority.namespace
                or compiled_scheme_digest_v1(compiled) != compiled.compiled_digest):
            return False
        # A process-local HMAC authenticates this issuer, but the candidate
        # must still have a durable original at every later boundary.
        return self._matches_compilation_original(authority, lease, compiled)

    def _matches_compilation_original(
            self, authority: AuthorityContext, lease: object,
            compiled: D12CompiledSchemeV1) -> bool:
        read = getattr(self._port, "read_compilation_original_v1", None)
        if not callable(read):
            return False
        original = read(authority, lease, compiled_digest=compiled.compiled_digest)
        return type(original) is D12CompiledSchemeV1 and original == compiled

    def _verified_preview_original(
            self, authority: AuthorityContext, lease: object,
            preview: D12PreviewCertificateV1) -> bool:
        if type(preview) is not D12PreviewCertificateV1:
            return False
        return self._matches_preview_original(authority, lease, preview)

    def _matches_preview_original(
            self, authority: AuthorityContext, lease: object,
            preview: D12PreviewCertificateV1) -> bool:
        read = getattr(self._port, "read_preview_original_v1", None)
        if not callable(read):
            return False
        original = read(authority, lease, preview_seal=preview.issuer_seal)
        return type(original) is D12PreviewCertificateV1 and original == preview

    @staticmethod
    def _current(frame: D12CurrentCreatorDraftV1,
                 authority: AuthorityContext) -> str:
        if type(frame) is not D12CurrentCreatorDraftV1:
            raise D12SchemeHold("W01 current creator draft frame is unavailable")
        try:
            key = AtomKey.from_token(frame.draft_ref)
            head = AtomKey.from_token(frame.active_head_ref)
        except (TypeError, ValueError) as exc:
            raise D12SchemeHold("creator draft or active head ref is invalid") from exc
        if (type(frame.draft) is not CharacterDraft
                or type(frame.namespace) is not NamespaceId
                or frame.namespace != authority.namespace
                or not frame.creator_authorized
                or key != character_draft_key(frame.namespace)
                or head != active_scheme_head_key(frame.namespace)
                or frame.draft.scope != key.owner.persona
                or type(frame.draft_revision) is not int or frame.draft_revision < 1
                or frame.draft.revision != frame.draft_revision
                or type(frame.active_head_revision) is not int
                or frame.active_head_revision < 0
                or any(type(item) is not int or item < 0 for item in (
                    frame.graph_revision, frame.access_epoch, frame.delete_epoch,
                ))):
            raise D12SchemeHold("creator Authority, current draft or head differs")
        return canonical_digest(frame.draft)

    @staticmethod
    def _authority(authority: AuthorityContext) -> None:
        if (type(authority) is not AuthorityContext
                or authority.issuer_domain != "d12"
                or "persona" not in authority.owner_scope):
            raise D12SchemeHold("creator Authority scope is unavailable")

    def read_current(self, authority: AuthorityContext, lease: object, *,
                     draft_ref: str, expected_graph_revision: int | None = None
                     ) -> D12CurrentCreatorDraftV1:
        """Return a detached current creator draft from W01's fenced read."""
        self._authority(authority)
        if (expected_graph_revision is not None
                and (type(expected_graph_revision) is not int
                     or expected_graph_revision < 0)):
            raise D12SchemeHold("invalid expected graph revision")

        def project(frame: D12CurrentCreatorDraftV1) -> D12CurrentCreatorDraftV1:
            self._current(frame, authority)
            if frame.draft_ref != draft_ref:
                raise D12SchemeHold("current creator draft ref differs")
            if (expected_graph_revision is not None
                    and frame.graph_revision != expected_graph_revision):
                raise D12SchemeHold("creator draft graph epoch changed",
                                    code="stale_graph_epoch")
            draft = CharacterDraft(
                frame.draft.scope, frame.draft.revision,
                json.loads(json.dumps(frame.draft.fields, allow_nan=False)),
                dict(frame.draft.field_sources),
            )
            return replace(frame, draft=draft)

        return self._port.with_current_creator_draft_v1(
            authority, lease, draft_ref=draft_ref,
            required_capability="workbench.create", project=project,
        )

    def compile_current(self, authority: AuthorityContext, lease: object, *,
                        draft_ref: str) -> D12CompiledSchemeV1:
        self._authority(authority)
        if not callable(getattr(self._port, "compile_domain_scheme_v1", None)):
            raise D12SchemeHold("trusted W01 domain compiler is unavailable")

        def project(frame: D12CurrentCreatorDraftV1) -> D12CompiledSchemeV1:
            draft_digest = self._current(frame, authority)
            if frame.draft_ref != draft_ref:
                raise D12SchemeHold("current creator draft ref differs")
            fields_by_domain: dict[str, list[tuple[str, object, str]]] = {}
            for name, value in frame.draft.fields.items():
                domain, separator, _ = name.partition(".")
                if (type(name) is not str or not separator
                        or domain not in _SCHEME_DOMAINS
                        or _FIELD_PATH.fullmatch(name) is None):
                    raise D12SchemeHold(
                        "draft field has no valid D01-D10 owner",
                        code="invalid_field_path",
                        diagnostics=(D12SchemeDiagnosticV1(
                            str(name), "invalid_field_path",
                            "Field must name an owned D01-D10 schema path"),),
                    )
                fields_by_domain.setdefault(domain, []).append(
                    (name, value, frame.draft.field_sources[name]),
                )
            if not fields_by_domain:
                raise D12SchemeHold("empty draft has no domain compilation")
            receipts = []
            for domain, field_values in sorted(fields_by_domain.items()):
                frozen = tuple(sorted(field_values, key=lambda item: item[0]))
                digest = canonical_digest((draft_digest, domain, frozen))
                receipt = self._port.compile_domain_scheme_v1(
                    domain=domain, fields=frozen, field_input_digest=digest,
                )
                if type(receipt) is D12DomainCompileRejectionV1:
                    if (receipt.status != "domain_rejected_candidate"
                            or receipt.domain != domain
                            or receipt.field_names != tuple(item[0] for item in frozen)
                            or receipt.field_input_digest != digest
                            or not receipt.diagnostics
                            or any(type(item) is not D12SchemeDiagnosticV1
                                   or item.field_path not in receipt.field_names
                                   for item in receipt.diagnostics)):
                        raise D12SchemeHold("domain compiler rejection is invalid")
                    raise D12SchemeHold(
                        "domain compiler rejected scheme fields",
                        code="domain_compile_rejected",
                        diagnostics=receipt.diagnostics,
                    )
                if (type(receipt) is not D12DomainCompileReceiptV1
                        or receipt.status != "domain_compiled_candidate"
                        or receipt.domain != domain
                        or receipt.field_names != tuple(item[0] for item in frozen)
                        or receipt.field_input_digest != digest
                        or not receipt.candidate_ref
                        or not re.fullmatch(r"[0-9a-f]{64}", receipt.proposal_schema_hash)):
                    raise D12SchemeHold("domain compiler did not cover draft fields")
                receipts.append(receipt)
            if self._current(frame, authority) != draft_digest:
                raise D12SchemeHold("draft changed during domain compilation")
            basis = (frame.namespace, frame.draft_ref, frame.draft_revision,
                     draft_digest, frame.active_head_ref,
                     frame.active_head_revision, frame.graph_revision,
                     frame.access_epoch, frame.delete_epoch, tuple(receipts))
            candidate = D12CompiledSchemeV1(
                *basis, canonical_digest(basis), "",
            )
            return replace(candidate, issuer_seal=self._seal(candidate))

        compiled = self._port.with_current_creator_draft_v1(
            authority, lease, draft_ref=draft_ref,
            required_capability="workbench.create", project=project,
        )
        recorder = getattr(self._port, "record_compilation_original_v1", None)
        if not callable(recorder):
            raise D12SchemeHold("trusted compilation original recorder is unavailable")
        recorder(authority, lease, compiled=compiled)
        if not self._matches_compilation_original(authority, lease, compiled):
            raise D12SchemeHold("durable compilation original is unavailable")
        return compiled

    def preview_isolated(self, authority: AuthorityContext, lease: object, *,
                         compiled: D12CompiledSchemeV1) -> D12PreviewCertificateV1:
        self._authority(authority)
        if not callable(getattr(self._port, "preview_isolated_scheme_v1", None)):
            raise D12SchemeHold("trusted W01 isolated preview is unavailable")
        if (type(compiled) is not D12CompiledSchemeV1
                or not self._verified_compilation_original(authority, lease, compiled)
                or compiled.namespace != authority.namespace):
            raise D12SchemeHold("compiled scheme is not issued for this creator")
        result = self._port.preview_isolated_scheme_v1(
            authority, lease, compiled=compiled,
        )
        if (type(result) is not D12IsolatedPreviewV1
                or result.status != "isolated_preview_only"
                or result.compiled_digest != compiled.compiled_digest
                or result.sandbox_namespace == authority.namespace
                or result.source_snapshot_digest != compiled.draft_digest
                or result.production_revision_before != result.production_revision_after
                or result.production_revision_before != compiled.graph_revision
                or result.external_effect_refs or result.formal_contribution_refs
                or result.production_write_refs or not result.actual_cost_receipt_ref):
            raise D12SchemeHold("experiment isolation or cost receipt is unavailable")
        certificate = D12PreviewCertificateV1(
            compiled.compiled_digest, result.sandbox_namespace,
            result.actual_cost_receipt_ref, "",
        )
        certificate = replace(certificate, issuer_seal=self._seal(certificate))
        recorder = getattr(self._port, "record_preview_original_v1", None)
        if not callable(recorder):
            raise D12SchemeHold("trusted preview original recorder is unavailable")
        recorder(authority, lease, compiled=compiled, result=result,
                 certificate=certificate)
        if not self._matches_preview_original(authority, lease, certificate):
            raise D12SchemeHold("durable preview original is unavailable")
        return certificate

    def prepare_adoption(self, authority: AuthorityContext, lease: object, *,
                         operation_id: str, compiled: D12CompiledSchemeV1,
                         preview: D12PreviewCertificateV1) -> D12SchemeAdoptionIntentV1:
        self._authority(authority)
        if (type(compiled) is not D12CompiledSchemeV1
                or type(preview) is not D12PreviewCertificateV1
                or not self._verified_compilation_original(authority, lease, compiled)
                or not self._verified_preview_original(authority, lease, preview)
                or compiled.namespace != authority.namespace
                or preview.compiled_digest != compiled.compiled_digest
                or type(operation_id) is not str or not operation_id):
            raise D12SchemeHold("creator compilation, preview or operation differs")

        def project(frame: D12CurrentCreatorDraftV1) -> D12SchemeAdoptionIntentV1:
            digest = self._current(frame, authority)
            if (frame.draft_ref != compiled.draft_ref
                    or frame.draft_revision != compiled.draft_revision
                    or digest != compiled.draft_digest
                    or frame.active_head_ref != compiled.active_head_ref
                    or frame.active_head_revision != compiled.active_head_revision
                    or frame.graph_revision != compiled.graph_revision
                    or frame.access_epoch != compiled.access_epoch
                    or frame.delete_epoch != compiled.delete_epoch):
                raise D12SchemeHold("draft or active scheme became stale")
            intent = D12SchemeAdoptionIntentV1(
                operation_id, authority.namespace, compiled.compiled_digest,
                frame.draft_ref, frame.draft_revision,
                frame.active_head_ref, frame.active_head_revision,
                frame.graph_revision,
                frame.access_epoch, frame.delete_epoch, preview.issuer_seal, "",
            )
            return replace(intent, issuer_seal=self._seal(intent))

        return self._port.with_current_creator_draft_v1(
            authority, lease, draft_ref=compiled.draft_ref,
            required_capability="workbench.create", project=project,
        )

    def adopt_current(self, authority: AuthorityContext, lease: object, *,
                      intent: D12SchemeAdoptionIntentV1) -> D12SchemeAdoptionReceiptV1:
        self._authority(authority)
        if not callable(getattr(self._port, "commit_current_scheme_v1", None)):
            raise D12SchemeHold("trusted W01 atomic adoption is unavailable")
        if (type(intent) is not D12SchemeAdoptionIntentV1
                or not self._verified(intent)
                or intent.namespace != authority.namespace):
            raise D12SchemeHold("W01 adoption intent is unavailable")
        # W01 must recheck the full read set and creator Authority in the same
        # transaction that advances the active head. A DTO cannot do that.
        receipt = self._port.commit_current_scheme_v1(
            authority, lease, intent=intent,
        )
        if (type(receipt) is not D12SchemeAdoptionReceiptV1
                or receipt.status != "coordinator_committed_scheme"
                or receipt.operation_id != intent.operation_id
                or receipt.namespace != intent.namespace
                or receipt.compiled_digest != intent.compiled_digest
                or receipt.previous_head_ref != intent.expected_active_head_ref
                or receipt.previous_head_revision != intent.expected_active_head_revision
                or receipt.active_head_revision <= receipt.previous_head_revision):
            raise D12SchemeHold("W01 atomic adoption receipt is unavailable")
        return receipt

    @staticmethod
    def prepare_rollback(authority: AuthorityContext, *, historical_plan_ref: str,
                         active_head_ref: str,
                         active_head_revision: int) -> D12RollbackDraftIntentV1:
        D12SchemeCommandIssuer._authority(authority)
        if (not historical_plan_ref or not active_head_ref
                or type(active_head_revision) is not int
                or active_head_revision < 1):
            raise D12SchemeHold("rollback requires a historical plan and current head")
        # W01 must stage a *new* administrative draft from authorized history,
        # then recompile and adopt it. Past experiences/effects stay committed.
        return D12RollbackDraftIntentV1(
            authority.namespace, historical_plan_ref,
            active_head_ref, active_head_revision,
        )


__all__ = [
    "D12CompiledSchemeV1", "D12CurrentCreatorDraftV1",
    "D12DraftUpdateDecisionV1", "plan_creator_draft_update_v1",
    "D12DomainCompileReceiptV1", "D12DomainCompileRejectionV1",
    "D12SchemeDiagnosticV1", "compiled_scheme_digest_v1",
    "D12IsolatedPreviewV1",
    "D12PreviewCertificateV1", "D12RollbackDraftIntentV1",
    "D12SchemeAdoptionIntentV1", "D12SchemeAdoptionReceiptV1",
    "D12SchemeCommandIssuer", "D12SchemeHold", "D12TrustedSchemePort",
    "D12CreatorDraftReadPort",
]
