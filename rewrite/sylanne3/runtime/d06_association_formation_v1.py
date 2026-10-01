"""One actual directed association from two adopted subjective meanings.

No model call or similarity score is issued here. W01 reads the real C02,
paid appraisal and current source/Owner closure, then commits the exact edge.
"""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, require_locator_v1, stage_result_v1
from ..domains.d04.affect import MeaningFacet, _decode_appraisal
from ..domains.d06 import D06DomainAdapter, D06DomainProvider
from ..domains.d06.pipeline import PreparedAssociation
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .c04_encoding_baseline_store_v3 import _receipt
from .d01_production_operations_v1 import (
    CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1,
    raw_head_value_v1, waiting_stage_v1,
)
from .d04_appraisal_driver_v3 import (
    read_current_d04_appraisal_original_v3, read_d04_appraisal_acceptance_v3,
    read_d04_original_v3,
)
from .d04_product_pipeline_v3 import ids
from .issuers import D11BudgetJobIssuer, D02ResourceIssuer
from .reply_model_job import read_settled_c02_reply_source_v1

POLICY = "d06.shared-adopted-meaning.v1"


@dataclass(frozen=True, slots=True)
class FormCurrentAssociationRequestV1:
    cue_source_ref: str
    cue_c02_operation_id: str
    related_source_ref: str
    related_c02_operation_id: str
    cue_appraisal_ref: str
    cue_facet_id: str
    related_appraisal_ref: str
    related_facet_id: str
    meaning_field: str

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            require_locator_v1(getattr(self, name), name)
        if self.meaning_field not in {"relation_meaning", "self_meaning"}:
            raise ValueError("association requires one installed subjective meaning field")
        if self.cue_source_ref == self.related_source_ref or self.cue_c02_operation_id == self.related_c02_operation_id:
            raise ValueError("association requires two distinct actual C02 sources")
        for ref, type_name in ((self.cue_source_ref, "memory.source"), (self.related_source_ref, "memory.source"),
                (self.cue_appraisal_ref, "d04.appraisal_bundle.v1"), (self.related_appraisal_ref, "d04.appraisal_bundle.v1")):
            if AtomKey.from_token(ref).type_name != type_name:
                raise ValueError("association locator names another installed type")


@dataclass(frozen=True, slots=True)
class AdoptedAssociationMeaningV1:
    source_ref: str
    c02_operation_id: str
    c02_receipt_digest: str
    c02_seal_digest: str
    appraisal_ref: str
    appraisal_revision: int
    acceptance_digest: str
    prepared_digest: str
    result_digest: str
    cost_digest: str
    facet: MeaningFacet
    interpretation_version: GraphVersion
    persona_versions: tuple[GraphVersion, ...]
    episode_versions: tuple[GraphVersion, ...]


@dataclass(frozen=True, slots=True)
class AssociationFormationEvidenceV1:
    cue: AdoptedAssociationMeaningV1
    related: AdoptedAssociationMeaningV1
    meaning_field: str
    meaning_value_digest: str
    basis_source_refs: tuple[str, ...]
    policy: str = POLICY


def _sides(request):
    return ((request.cue_source_ref, request.cue_c02_operation_id, request.cue_appraisal_ref, request.cue_facet_id),
        (request.related_source_ref, request.related_c02_operation_id, request.related_appraisal_ref, request.related_facet_id))


def _appraisal_evidence(db, ns, side):
    """Authenticate the committed paid stage, independent of today's full snapshot."""
    source_ref, c02_id, appraisal_ref, facet_id = side
    acceptance = read_d04_appraisal_acceptance_v3(db, ns, appraisal_ref)
    if acceptance is None:
        raise MissingProductionOriginalV1("actual_adopted_appraisal:" + appraisal_ref)
    identity = ids(ns, c02_id)
    original = read_current_d04_appraisal_original_v3(db, ns, identity["job"])
    if original is None or original.digest != acceptance.prepared_digest or acceptance.operation_id != identity["operation"]:
        raise ValueError("association appraisal has another actual C02 preparation")
    frozen = json.loads(original.frozen_json)["input"]
    if source_ref not in tuple(item["source_ref"]["ref"] for item in frozen["sources"]):
        raise ValueError("association appraisal preparation does not include its C02 Source")
    adopt_id = "d04-adopt:" + identity["operation"]
    stage = db.execute("SELECT c02_operation_id,source_ref,receipt_json FROM graph_d04_installed_stage_attempts_v3 "
        "WHERE bot=? AND persona=? AND operation_id=? AND stage='adopt'", (*ns.as_tuple, adopt_id)).fetchone()
    if (stage is None or stage[:2] != (c02_id, source_ref) or stage[2] is None
            or json.loads(stage[2]).get("status") != "adopted"
            or json.loads(stage[2]).get("appraisal_ref") != appraisal_ref
            or json.loads(stage[2]).get("appraisal_original_digest") != acceptance.digest):
        raise ValueError("association requires the actual accepted installed appraisal stage")
    receipt = _receipt(db, ns, adopt_id)
    version = GraphVersion(AtomKey.from_token(appraisal_ref), acceptance.appraisal_revision)
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (appraisal_ref, acceptance.appraisal_revision)).fetchone()
    if (version not in receipt.write_versions or history is None or history[0] != adopt_id
            or history[2] != 1 or canonical_serialize(json.loads(history[1])) != acceptance.appraisal_value_json):
        raise ValueError("association appraisal is not the actual committed Graph member")
    cost = read_d04_original_v3(db, ns, "appraisal_cost", acceptance.cost_original_ref)
    result = read_d04_original_v3(db, ns, "appraisal_result", acceptance.result_original_ref)
    if (cost is None or result is None or cost[1] != acceptance.cost_original_digest
            or result[1] != acceptance.result_original_digest or cost[0]["paid"] is not True
            or cost[0]["prepared_digest"] != original.digest
            or cost[0]["result_original_ref"] != acceptance.result_original_ref
            or cost[0]["result_original_digest"] != result[1]):
        raise ValueError("association appraisal lost its actual paid result originals")
    bundle = _decode_appraisal(json.loads(acceptance.appraisal_value_json))
    facets = tuple(facet for facet in bundle.meaning_facets if facet.facet_id == facet_id)
    if len(facets) != 1 or source_ref not in facets[0].source_refs or source_ref not in bundle.source_refs:
        raise ValueError("association facet does not explicitly cite its actual Source")
    interpretation = next((item["ref"] for item in frozen["interpretations"]
        if item["ref"]["ref"] == facets[0].interpretation_ref), None)
    if interpretation is None:
        raise ValueError("association facet names no original interpretation")
    persona = tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in original.read_rows
        if AtomKey.from_token(row.ref).type_name in {"d01.persona_plan.v1", "d01.persona_activation.v1"})
    if len(persona) != 2:
        raise ValueError("association appraisal has no exact persona definition and activation")
    return acceptance, facets[0], GraphVersion(AtomKey.from_token(interpretation["ref"]), interpretation["version"]), persona


def _basis_and_keys(db, ns, request):
    roots = {request.cue_source_ref, request.related_source_ref}
    keys = [owner_grant_key(*ns.as_tuple)]
    for source, c02, appraisal, facet in _sides(request):
        keys.extend((AtomKey.from_token(source), AtomKey.from_token(appraisal)))
        raw = raw_head_value_v1(db, ns, AtomKey.from_token(appraisal))
        if raw:
            roots.update(raw["source_refs"])
        acceptance = read_d04_appraisal_acceptance_v3(db, ns, appraisal)
        if acceptance is not None:
            _, _, interpretation, persona = _appraisal_evidence(db, ns, (source, c02, appraisal, facet))
            keys.extend((interpretation.key, *(version.key for version in persona)))
        if db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, c02)).fetchone():
            keys.extend(version.key for version in _receipt(db, ns, c02).write_versions
                if version.key.type_name in {"memory.episode.v1", "memory.subjective_trace.v2"})
    refs = tuple(sorted(roots))
    adapter = D06DomainAdapter(ns)
    output = adapter.association_identity(AtomKey.from_token(request.cue_source_ref).owner.subject,
        AtomKey.from_token(request.related_source_ref).owner.subject,
        tuple(AtomKey.from_token(ref).owner.subject for ref in refs), kind="subjective_meaning", content_reality="subjective")
    return refs, tuple((*keys, output)), output


def read_plan_current_d06_association_v1(db, *, namespace, activity_id, operation_kind, request):
    if not db.in_transaction or operation_kind != "form_association" or type(request) is not FormCurrentAssociationRequestV1:
        raise ValueError("actual registered association read plan required")
    roots, keys, _ = _basis_and_keys(db, namespace, request)
    return production_read_plan_v1((), keys, roots, (request.cue_source_ref, request.related_source_ref))


class InstalledD06AssociationReadersV1:
    def __init__(self, *, issuer, resource_issuer):
        if type(issuer) is not D11BudgetJobIssuer or type(resource_issuer) is not D02ResourceIssuer:
            raise TypeError("association formation requires this installation's actual issuers")
        self.issuer, self.resource_issuer = issuer, resource_issuer

    def read_current(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        ns = frame.envelope.authority.namespace
        roots, _, output = _basis_and_keys(db, ns, request)
        family = read.source_family(db, roots, purpose="consolidation")
        evidence = []
        for side in _sides(request):
            source_ref, c02_id, appraisal_ref, _ = side
            if db.execute("SELECT 1 FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, c02_id)).fetchone() is None:
                raise MissingProductionOriginalV1("actual_settled_c02:" + c02_id)
            c02 = _receipt(db, ns, c02_id)
            read_settled_c02_reply_source_v1(db, self.resource_issuer, ns, c02, source_ref, frame.snapshot)
            acceptance, facet, interpretation, persona = _appraisal_evidence(db, ns, side)
            appraisal = read.head(db, appraisal_ref, required=True)
            if (appraisal.revision != acceptance.appraisal_revision
                    or canonical_serialize(appraisal.value) != acceptance.appraisal_value_json):
                raise MissingProductionOriginalV1("current_adopted_appraisal:" + appraisal_ref)
            for version in (interpretation, *persona):
                atom = read.head(db, version.key, required=True)
                if atom.revision != version.revision:
                    raise MissingProductionOriginalV1("current_appraisal_meaning_basis:" + version.key.token)
            if request.meaning_field in facet.unknown_fields or not getattr(facet, request.meaning_field):
                raise MissingProductionOriginalV1("known_adopted_subjective_meaning:" + appraisal_ref)
            seal = db.execute("SELECT bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, c02_id)).fetchone()
            episodes = tuple(version for version in c02.write_versions if version.key.type_name in {"memory.episode.v1", "memory.subjective_trace.v2"})
            for version in episodes:
                read.head(db, version.key, required=True)
            evidence.append(AdoptedAssociationMeaningV1(source_ref, c02_id, canonical_digest(c02), seal[0], appraisal_ref,
                appraisal.revision, acceptance.digest, acceptance.prepared_digest, acceptance.result_original_digest,
                acceptance.cost_original_digest, facet, interpretation, tuple(sorted(persona, key=lambda row:row.key.token)), episodes))
        cue, related = evidence
        if (cue.facet.target_ref != related.facet.target_ref or cue.facet.value_ref != related.facet.value_ref
                or cue.persona_versions != related.persona_versions
                or getattr(cue.facet, request.meaning_field) != getattr(related.facet, request.meaning_field)):
            raise MissingProductionOriginalV1("exact_shared_adopted_subjective_meaning")
        absent = read.head(db, output)
        if absent.revision != 0:
            raise MissingProductionOriginalV1("association_true_absence")
        formation = AssociationFormationEvidenceV1(cue, related, request.meaning_field,
            canonical_digest(getattr(cue.facet, request.meaning_field)), roots)
        proof = tuple(version for version in frame.snapshot.versions if version.revision > 0)
        prepared = PreparedAssociation(family[request.cue_source_ref].source_id,
            family[request.related_source_ref].source_id, tuple(family[ref].source_id for ref in roots),
            proof, frame.snapshot.epochs[0])
        return formation, prepared


def stage_form_current_association_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD06AssociationReadersV1:
        raise TypeError("actual installed association readers required")
    try:
        formation, prepared = installed_readers.read_current(db, frame, request)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d06", "form_association", request, missing)
    adapter = D06DomainAdapter(frame.envelope.authority.namespace)
    proposal = adapter.compile_association(frame.envelope, prepared, kind="subjective_meaning", weight=1.0,
        context_tags=(), content_reality="subjective")
    provider = D06DomainProvider()
    stage = stage_result_v1(frame, "d06", "form_association", request, writes=proposal.typed_writes,
        provenance={"formation": formation}, contribution_keys=proposal.contribution_keys,
        proposal_schema=proposal.proposal_schema, proposal_hash=proposal.proposal_schema_hash)
    # The association compiler's historical Access and formation proofs are
    # required; the generic staging helper's Source-only projection is shorter.
    stage = replace(stage, proposals=(proposal,))
    provider.validate(proposal, frame.snapshot)
    return stage


def decode_association_formation_evidence_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, AssociationFormationEvidenceV1)
    cue, related = value.cue, value.related
    if (value.policy != POLICY or value.meaning_field not in {"relation_meaning", "self_meaning"}
            or cue.source_ref == related.source_ref or cue.c02_operation_id == related.c02_operation_id
            or cue.facet.target_ref != related.facet.target_ref or cue.facet.value_ref != related.facet.value_ref
            or cue.persona_versions != related.persona_versions
            or not getattr(cue.facet, value.meaning_field)
            or getattr(cue.facet, value.meaning_field) != getattr(related.facet, value.meaning_field)
            or value.meaning_value_digest != canonical_digest(getattr(cue.facet, value.meaning_field))
            or value.basis_source_refs != tuple(sorted(set(value.basis_source_refs)))
            or not {cue.source_ref, related.source_ref} <= set(value.basis_source_refs)):
        raise ValueError("association formation differs from the installed exact meaning policy")
    for side in (cue, related):
        if (value.meaning_field in side.facet.unknown_fields or side.source_ref not in side.facet.source_refs
                or side.appraisal_revision < 1 or len(side.persona_versions) != 2 or len(side.episode_versions) != 2
                or side.interpretation_version.key.token != side.facet.interpretation_ref):
            raise ValueError("association formation lacks its exact adopted meaning basis")
        for digest in (side.c02_receipt_digest, side.c02_seal_digest, side.acceptance_digest,
                side.prepared_digest, side.result_digest, side.cost_digest):
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError("association formation original commitment differs")
    return value


def validate_association_formation_original_joins_v1(db):
    """C09 checks existing formation rows against their actual immutable history."""
    from ..runtime_contracts import NamespaceId
    from .domain_production_originals_v1 import _receipt as production_receipt
    rows = db.execute("SELECT bot,persona,operation_id,original_payload_json,original_digest,receipt_json,receipt_digest "
        "FROM graph_domain_production_originals_v1 "
        "WHERE domain='d06' AND operation_kind='form_association'").fetchall()
    for bot, persona, operation, wire, digest, receipt_wire, receipt_digest in rows:
        ns = NamespaceId(bot, persona)
        payload = json.loads(wire)
        receipt = production_receipt(json.loads(receipt_wire))
        actual = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, operation)).fetchone()
        if (canonical_serialize(payload) != wire or canonical_digest(payload) != digest
                or canonical_digest(receipt) != receipt_digest or receipt.operation_id != operation
                or actual != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq)):
            raise ValueError("association formation original lost its actual committed receipt")
        if not payload["provenance"]:
            if payload["writes"]:
                raise ValueError("waiting association cannot contain a Graph edge")
            continue
        evidence = decode_association_formation_evidence_v1(payload["provenance"]["formation"])
        request = FormCurrentAssociationRequestV1(**payload["request"])
        for locator, side in zip(_sides(request), (evidence.cue, evidence.related), strict=True):
            acceptance, facet, interpretation, persona_versions = _appraisal_evidence(db, ns, locator)
            c02 = _receipt(db, ns, side.c02_operation_id)
            seal = db.execute("SELECT bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?",
                (*ns.as_tuple, side.c02_operation_id)).fetchone()
            if ((side.source_ref, side.c02_operation_id, side.appraisal_ref, side.facet.facet_id) != locator
                    or side.acceptance_digest != acceptance.digest or side.prepared_digest != acceptance.prepared_digest
                    or side.result_digest != acceptance.result_original_digest or side.cost_digest != acceptance.cost_original_digest
                    or side.appraisal_revision != acceptance.appraisal_revision or side.facet != facet
                    or side.interpretation_version != interpretation
                    or side.persona_versions != tuple(sorted(persona_versions, key=lambda row:row.key.token))
                    or side.c02_receipt_digest != canonical_digest(c02) or seal != (side.c02_seal_digest,)
                    or side.episode_versions != tuple(version for version in c02.write_versions
                        if version.key.type_name in {"memory.episode.v1", "memory.subjective_trace.v2"})):
                raise ValueError("association formation lost its actual C02/appraisal provenance join")
        source, target = (AtomKey.from_token(ref).owner.subject for ref in (request.cue_source_ref, request.related_source_ref))
        key = D06DomainAdapter(ns).association_identity(source, target,
            tuple(AtomKey.from_token(ref).owner.subject for ref in evidence.basis_source_refs),
            kind="subjective_meaning", content_reality="subjective")
        versions = tuple(version for version in receipt.write_versions if version.key == key)
        if len(versions) != 1 or len(payload["writes"]) != 1 or payload["writes"][0]["key"] != key.token:
            raise ValueError("association formation has no exact committed edge member")
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (key.token, versions[0].revision)).fetchone()
        if (history is None or history[0] != operation or history[2] != 1
                or json.loads(history[1]) != payload["writes"][0]["value"]):
            raise ValueError("association edge differs from its actual formation receipt history")
    return True
