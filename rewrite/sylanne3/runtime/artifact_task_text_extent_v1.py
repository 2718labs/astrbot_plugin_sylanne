"""Owner registration of an explicit, task-bound whole-method Chinese text range."""
from dataclasses import dataclass,field
import json
from .artifact_task_amendment_v1 import ArtifactTaskAmendmentBasisV1
import re

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import _decode_goal
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..model_broker.artifact_draft_v1 import ArtifactDraftTextExtentV2, MAX_TEXT_BYTES
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import (
    CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1, raw_head_value_v1)
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d11_life_preparation_v1 import _read, _record

PRODUCER_KIND = "register_artifact_task_text_extent"
OPERATION_KIND = "input:" + PRODUCER_KIND
KIND = "artifact_task_text_extent"
UNIT = "non-whitespace-codepoints"
GRAMMAR = "d08.artifact-task-full-text-extent.zh.v1"


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("task text extent requires an exact original digest")


@dataclass(frozen=True, slots=True)
class RegisterArtifactTaskTextExtentRequestV1:
    goal_ref: str
    expected_goal_revision: int

    def __post_init__(self):
        if (AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or type(self.expected_goal_revision) is not int or self.expected_goal_revision < 1):
            raise ValueError("text extent registration accepts only the actual current Goal selector")


@dataclass(frozen=True, slots=True)
class ArtifactTaskTextExtentOriginalV1:
    namespace: NamespaceId
    goal_head: GraphVersion
    goal_digest: str
    objective_ref: str
    objective_digest: str
    task_source_head: GraphVersion
    task_source_digest: str
    task_c02_operation_id: str
    c1_intent_ref: str
    c1_intent_digest: str
    task_producer_ref: str
    task_producer_digest: str
    registration_operation_id: str
    owner_guard: ProductionOwnerGuardV1
    evidence_start: int
    evidence_end: int
    evidence_text: str
    full_extent: ArtifactDraftTextExtentV2
    unit: str = UNIT
    evidence_grammar: str = GRAMMAR
    schema: str = "d08.artifact-task-text-extent-original.v1"

    def __post_init__(self):
        if self.schema!="d08.artifact-task-text-extent-original.v1":
            raise ValueError("exact original V1 task text extent schema required")
        _validate_task_text_extent_fields_v1(self)


def _validate_task_text_extent_fields_v1(value):
    if (type(value.namespace) is not NamespaceId or type(value.owner_guard) is not ProductionOwnerGuardV1
            or type(value.full_extent) is not ArtifactDraftTextExtentV2
            or value.unit!=UNIT or value.evidence_grammar!=GRAMMAR
            or type(value.evidence_start) is not int or type(value.evidence_end) is not int
            or not 0<=value.evidence_start<value.evidence_end
            or type(value.evidence_text) is not str or len(value.evidence_text)!=value.evidence_end-value.evidence_start
            or not 1<=len(value.evidence_text.encode())<=4096):
        raise ValueError("closed task-bound original range and source evidence required")
    for head,kind in ((value.goal_head,"d08.goal.v1"),(value.task_source_head,"memory.source")):
        if (type(head) is not GraphVersion or head.revision<1 or head.key.type_name!=kind
                or NamespaceId.from_key(head.key)!=value.namespace):
            raise ValueError("text extent crossed its positive Goal/Source scope")
    for digest in (value.goal_digest,value.objective_digest,value.task_source_digest,value.c1_intent_digest,value.task_producer_digest):
        _digest(digest)
    for ref in (value.objective_ref,value.task_c02_operation_id,value.c1_intent_ref,value.task_producer_ref,value.registration_operation_id):
        if type(ref) is not str or not ref or len(ref.encode())>4096:
            raise ValueError("text extent requires its bounded actual producer selectors")


def artifact_task_text_extent_ref_v1(value):
    if type(value) is ArtifactTaskTextExtentOriginalV2:return artifact_task_text_extent_ref_v2(value)
    return "artifact-task-text-extent:" + canonical_digest((value.namespace, value.goal_head,
        value.goal_digest, value.objective_digest, value.task_source_head, value.task_source_digest,
        value.full_extent, value.evidence_grammar))[:48]


_RANGE = r"(?:全文|正文|目标文本|目标全文|目标正文|目标字数|全文字数|正文字数)(?:的字数)?(?:为|控制在|限制在|限制为|应为|：|:)?\s*(?P<minimum>[1-9][0-9]{0,4})\s*(?:-|—|–|~|～|至|到)\s*(?P<maximum>[1-9][0-9]{0,4})\s*字"
_TASK = r"(?:请)?(?:先)?(?:写|起草|撰写|生成)(?:一篇|一份|一个)?(?:初稿|草稿|正文|全文|文章|文稿|稿件)"
_REVISION = r"(?:稍后|之后|随后|再)(?:我(?:会|将)?(?:给(?:出)?|提供|提出)(?:修改意见|修订意见)|(?:按|根据)(?:修改意见|修订意见)(?:修改|修订))"
_SEP = r"[\s，,；;。.!！]*"
_RANGE_RE = re.compile(_RANGE)
_TASK_RE = re.compile(_TASK + _SEP + "(?:" + _RANGE + _SEP + ")?" + "(?:" + _REVISION + _SEP + ")?")


def _explicit_zh_extent_v1(text, task_quote):
    # The complete direct task grammar, exact C1 quote and objective/source joins
    # establish task membership. A quoted numeric substring alone establishes none.
    if any(mark in text for mark in ('"', "'", "`", "“", "”", "‘", "’")) or re.search(r"\bwords?\b", text, re.I):
        raise MissingProductionOriginalV1("unambiguous_direct_chinese_task_text_extent")
    quote_start = text.find(task_quote)
    if quote_start < 0 or text.find(task_quote, quote_start + 1) >= 0:
        raise MissingProductionOriginalV1("unique_actual_task_intent_evidence_span")
    if _TASK_RE.fullmatch(task_quote.strip()) is None:
        raise MissingProductionOriginalV1("explicit_supported_direct_task_extent_grammar")
    matches = tuple(_RANGE_RE.finditer(text))
    if len(matches) != 1:
        raise MissingProductionOriginalV1("single_explicit_current_task_full_text_range")
    match = matches[0]
    outside_quote = (text[:quote_start] + text[quote_start + len(task_quote):]).strip(" \t\r\n，,；;。.!！")
    if outside_quote and _RANGE_RE.fullmatch(outside_quote) is None:
        raise MissingProductionOriginalV1("range_belongs_to_only_the_actual_direct_task")
    minimum, maximum = int(match["minimum"]), int(match["maximum"])
    if not 1 <= minimum <= maximum <= MAX_TEXT_BYTES:
        raise MissingProductionOriginalV1("bounded_explicit_current_task_full_text_extent")
    return ArtifactDraftTextExtentV2(minimum, maximum), match.start(), match.end(), match.group()


def _objective_basis_v1(db, namespace, goal_ref, goal, issuer):
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    objective_ref, objective = require_artifact_task_objective_original_v1(db,
        namespace=namespace, goal_ref=goal_ref, goal=goal, issuer=issuer)
    row = _read(db, issuer=issuer, namespace=namespace, kind="artifact_task_objective", ref=objective_ref)
    producer = read_adopted_domain_operation_v1(db, namespace, row[1])
    return objective_ref, objective, producer


def read_plan_artifact_task_text_extent_v1(db, *, namespace, request, installed_readers):
    from .d08_personal_candidate_v1 import _readers
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    readers = _readers(installed_readers)
    if type(request) is not RegisterArtifactTaskTextExtentRequestV1:
        raise TypeError("exact text extent Goal registration selector required")
    task=readonly_current_artifact_task_text_extent_task_v2(db,namespace=namespace,request=request,issuer=readers.issuer)
    if task is not None:return _read_plan_amended_artifact_task_text_extent_v2(db,namespace=namespace,request=request,
        task=task,issuer=readers.issuer)
    keys = (owner_grant_key(*namespace.as_tuple), AtomKey.from_token(request.goal_ref))
    raw_goal = raw_head_value_v1(db, namespace, keys[1])
    if raw_goal is None:
        return production_read_plan_v1((), keys)
    ref, objective, producer = _objective_basis_v1(db, namespace, request.goal_ref, _decode_goal(raw_goal), readers.issuer)
    return production_read_plan_v1((), keys, (objective["source_ref"],),
        (ref, c1_task_intent_ref_v1(namespace, objective["initial_c02_operation_id"]),
         "d10-current:" + producer["original_digest"][:48]))


def _qualified_extent_v1(db, *, frame, request, readers, registration_operation_id):
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1, c1_task_intent_ref_v1
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    task=readonly_current_artifact_task_text_extent_task_v2(db,namespace=ns,request=request,issuer=readers.issuer)
    if task is not None:
        return _qualified_amended_artifact_task_text_extent_v2(db,frame=frame,request=request,readers=readers,
            registration_operation_id=registration_operation_id)
    atom = read.head(db, request.goal_ref, required=True)
    goal = _decode_goal(atom.value)
    if atom.revision != request.expected_goal_revision or goal.state != "active":
        raise MissingProductionOriginalV1("current_active_task_extent_goal")
    ref, objective, producer = _objective_basis_v1(db, ns, request.goal_ref, goal, readers.issuer)
    if ((objective["installation_id"], objective["manifest_digest"]) !=
            (readers.bundle.installation_policy.installation_id, readers.bundle.installation_policy.manifest_digest)
            or frame.now_utc >= objective["valid_until_utc"]):
        raise MissingProductionOriginalV1("current_installed_unexpired_task_extent_objective")
    read.original(ref, kind="d11.life_artifact_task_objective", digest=canonical_digest(objective))
    producer_ref = "d10-current:" + producer["original_digest"][:48]
    read.original(producer_ref, kind="d10.current-derive_ingress_artifact_task_scope_v1", digest=producer["original_digest"])
    intent = read_c1_task_intent_original_v1(db, namespace=ns,
        c02_operation_id=objective["initial_c02_operation_id"], issuer=readers.issuer)
    if (intent is None or intent.intent.kind != "draft_then_corrected_revision"
            or (intent.source_ref, intent.source_revision, intent.source_digest) !=
               (objective["source_ref"], objective["source_revision"], objective["source_digest"])):
        raise MissingProductionOriginalV1("actual_paid_C1_for_exact_task_extent_objective")
    c1_ref = c1_task_intent_ref_v1(ns, intent.c02_operation_id)
    read.original(c1_ref, kind="d11.life_c1_task_intent", digest=canonical_digest(plain_v1(intent)))
    source = read.head(db, intent.source_ref, required=True)
    records = read.source_family(db, (intent.source_ref,))
    if (source.revision, canonical_digest(source.value)) != (intent.source_revision, intent.source_digest):
        raise MissingProductionOriginalV1("current_unmodified_task_extent_source")
    extent, start, end, evidence = _explicit_zh_extent_v1(records[intent.source_ref].text, intent.intent.source_quote)
    return ArtifactTaskTextExtentOriginalV1(ns, GraphVersion(atom.key, atom.revision), canonical_digest(atom.value),
        ref, canonical_digest(objective), GraphVersion(source.key, source.revision), canonical_digest(source.value),
        intent.c02_operation_id, c1_ref, canonical_digest(plain_v1(intent)), producer_ref, producer["original_digest"],
        registration_operation_id, frame.owner_guard, start, end, evidence, extent)


def stage_register_artifact_task_text_extent_v1(db, *, frame, request, installed_readers):
    from .d08_personal_candidate_v1 import _readers
    readers = _readers(installed_readers)
    if type(request) is not RegisterArtifactTaskTextExtentRequestV1:
        raise TypeError("exact task extent Owner selector required")
    try:
        value = _qualified_extent_v1(db, frame=frame, request=request, readers=readers,
            registration_operation_id=frame.envelope.identity.operation_id)
    except MissingProductionOriginalV1 as missing:
        return stage_result_v1(frame, "d08", OPERATION_KIND, request, coverage="waiting_for_original",
            missing=missing.missing_inputs, continuation=missing.continuation_ref)
    return stage_result_v1(frame, "d08", OPERATION_KIND, request,
        provenance={"artifact_task_text_extent": value})


def require_artifact_task_text_extent_history_v1(db, *, namespace, original_ref, producing_operation_id, raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_artifact_task_text_extent_original_v1(raw)
    if type(value) is ArtifactTaskTextExtentOriginalV2:
        return require_artifact_task_text_extent_history_v2(db,namespace=namespace,original_ref=original_ref,
            producing_operation_id=producing_operation_id,raw=raw)
    adopted = read_adopted_domain_operation_v1(db, namespace, producing_operation_id)
    if (value.namespace != namespace or artifact_task_text_extent_ref_v1(value) != original_ref
            or value.registration_operation_id != producing_operation_id
            or adopted is None or (adopted["domain"], adopted["operation_kind"]) != ("d08", OPERATION_KIND)
            or adopted["payload"]["coverage"] != "complete"
            or adopted["payload"]["provenance"] != {"artifact_task_text_extent": raw}
            or adopted["payload"]["request"] != plain_v1(RegisterArtifactTaskTextExtentRequestV1(
                value.goal_head.key.token, value.goal_head.revision))):
        raise ValueError("task text extent has no exact actual adopted Owner registration")
    return value


def record_artifact_task_text_extent_after_cas_v1(db, *, frame, stage, receipt, issuer):
    if (stage.domain, stage.operation_kind, stage.coverage) != ("d08", OPERATION_KIND, "complete"):
        return None
    if receipt.status != "committed" or receipt.operation_id != stage.operation_id:
        raise ValueError("task text extent requires its actual same-transaction Owner CAS receipt")
    adopted = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, stage.operation_id)
    if adopted is None or adopted["original_digest"] != stage.original_digest or adopted["receipt"] != receipt:
        raise ValueError("task text extent producer was not adopted by its actual W01 event")
    raw = adopted["payload"]["provenance"]["artifact_task_text_extent"]
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_artifact_task_text_extent_original_v1(raw)
    ref = artifact_task_text_extent_ref_v1(value)
    require_artifact_task_text_extent_history_v1(db, namespace=value.namespace, original_ref=ref,
        producing_operation_id=receipt.operation_id, raw=raw)
    return _record(db, issuer=issuer, namespace=value.namespace, kind=KIND, ref=ref,
        operation_id=receipt.operation_id, value=value)


def read_plan_personal_candidate_text_extents_v1(db, *, namespace, request, installed_readers):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    from .d08_personal_candidate_v1 import _readers
    readers = _readers(installed_readers)
    keys, roots, originals = [], [], []
    for binding in request.bindings:
        if type(binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            continue
        originals.append(binding.extent_original_ref)
        if type(binding) is ArtifactPhaseCandidateBindingV3:
            from .artifact_phase_postconditions_v1 import POLICY_KIND,decode_artifact_phase_postcondition_original_v1
            originals.append(binding.postcondition_policy_ref)
            policy_row=_read(db,issuer=readers.issuer,namespace=namespace,kind=POLICY_KIND,ref=binding.postcondition_policy_ref)
            if policy_row is not None:
                policy=decode_artifact_phase_postcondition_original_v1(POLICY_KIND,policy_row[0])
                keys.extend((policy.goal_head.key,policy.plan_head.key,policy.source_head.key))
                roots.append(policy.source_head.key.token)
                originals.append(policy.objective_ref)
        stored = _read(db, issuer=readers.issuer, namespace=namespace, kind=KIND, ref=binding.extent_original_ref)
        if stored is None:
            continue
        value = require_artifact_task_text_extent_history_v1(db, namespace=namespace,
            original_ref=binding.extent_original_ref, producing_operation_id=stored[1], raw=stored[0])
        keys.extend((value.goal_head.key, value.task_source_head.key))
        roots.append(value.task_source_head.key.token)
        originals.extend((value.objective_ref, value.c1_intent_ref, value.task_producer_ref,
            value.registration_operation_id))
        if type(value) is ArtifactTaskTextExtentOriginalV2:
            extra=_read_plan_amended_artifact_task_text_extent_v2(db,namespace=namespace,
                request=RegisterArtifactTaskTextExtentRequestV1(value.goal_head.key.token,value.goal_head.revision),
                task=value.basis.task,issuer=readers.issuer)
            keys.extend(extra.exact_keys);roots.extend(extra.source_roots);originals.extend(extra.required_original_refs)
    return production_read_plan_v1((), keys, roots, originals)


def require_current_artifact_task_text_extent_v1(db, *, frame, binding, goal_ref, installed_readers):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    from .d08_personal_candidate_v1 import _readers
    readers = _readers(installed_readers)
    if type(binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
        raise MissingProductionOriginalV1("actual_whole_method_task_text_extent_original")
    ns = frame.envelope.authority.namespace
    read = CurrentDomainReadV1(frame)
    stored = _read(db, issuer=readers.issuer, namespace=ns, kind=KIND, ref=binding.extent_original_ref)
    if stored is None:
        raise MissingProductionOriginalV1("actual_registered_task_full_text_extent")
    value = require_artifact_task_text_extent_history_v1(db, namespace=ns, original_ref=binding.extent_original_ref,
        producing_operation_id=stored[1], raw=stored[0])
    read.original(binding.extent_original_ref, kind="d11.life_" + KIND, digest=binding.extent_original_digest)
    adopted = read_adopted_domain_operation_v1(db, ns, stored[1])
    read.original(stored[1], kind="d08.current-" + OPERATION_KIND, digest=adopted["original_digest"])
    current = _qualified_extent_v1(db, frame=frame,
        request=RegisterArtifactTaskTextExtentRequestV1(goal_ref, value.goal_head.revision), readers=readers,
        registration_operation_id=value.registration_operation_id)
    objective = _read(db, issuer=readers.issuer, namespace=ns, kind="artifact_task_objective", ref=value.objective_ref)[0]
    expected_root=(value.basis.task.root_registration_ref if type(value) is ArtifactTaskTextExtentOriginalV2
        else objective["initial_root_registration_ref"])
    if (value != current or canonical_digest(plain_v1(value)) != binding.extent_original_digest
            or binding.task.namespace != ns or binding.task.c02_operation_id != value.task_c02_operation_id
            or binding.task.root_registration_ref != expected_root
            or binding.full_extent != value.full_extent):
        raise MissingProductionOriginalV1("current_exact_task_bound_whole_method_text_extent")
    if type(binding) is ArtifactPhaseCandidateBindingV3:
        from .artifact_phase_postconditions_v1 import (POLICY_KIND,decode_artifact_phase_postcondition_original_v1,
            require_current_artifact_phase_postcondition_policy_v1)
        policy_row=_read(db,issuer=readers.issuer,namespace=ns,kind=POLICY_KIND,ref=binding.postcondition_policy_ref)
        if policy_row is None:raise MissingProductionOriginalV1("actual_V3_preDecision_postcondition_policy")
        policy=decode_artifact_phase_postcondition_original_v1(POLICY_KIND,policy_row[0])
        require_current_artifact_phase_postcondition_policy_v1(db,frame=frame,binding=binding,
            goal_ref=goal_ref,plan_ref=policy.request.plan_ref,installed_readers=readers)
    return value


@dataclass(frozen=True,slots=True)
class ArtifactTaskTextExtentOriginalV2(ArtifactTaskTextExtentOriginalV1):
    basis:ArtifactTaskAmendmentBasisV1=field(kw_only=True)
    extent_mode:str=field(kw_only=True)
    rule_source_head:GraphVersion=field(kw_only=True)
    rule_source_digest:str=field(kw_only=True)
    rule_c1_intent_ref:str=field(kw_only=True)
    rule_c1_intent_digest:str=field(kw_only=True)
    amendment_evidence_start:int=field(kw_only=True)
    amendment_evidence_end:int=field(kw_only=True)
    amendment_evidence_text:str=field(kw_only=True)
    schema:str='d08.artifact-task-text-extent-original.v2'

    @property
    def original_deadline_utc(self):return self.basis.original_deadline_utc

    def __post_init__(self):
        if self.schema!='d08.artifact-task-text-extent-original.v2' or type(self.basis) is not ArtifactTaskAmendmentBasisV1:
            raise ValueError('amended extent requires its exact closed V2 basis')
        _validate_task_text_extent_fields_v1(self)
        if (self.extent_mode not in {'inherited','amended'} or type(self.rule_source_head) is not GraphVersion
                or self.rule_source_head.revision<1 or self.rule_source_head.key.type_name!='memory.source'
                or NamespaceId.from_key(self.rule_source_head.key)!=self.namespace
                or (self.goal_head,self.goal_digest,self.objective_ref,self.objective_digest,self.task_source_head,self.task_source_digest,
                    self.task_c02_operation_id,self.c1_intent_ref,self.c1_intent_digest,self.owner_guard)!=(
                    self.basis.goal_head,self.basis.goal_digest,self.basis.objective_ref,self.basis.objective_digest,
                    self.basis.amendment_source_head,self.basis.amendment_source_digest,self.basis.task.c02_operation_id,
                    self.basis.c1_intent_ref,self.basis.c1_intent_digest,self.basis.owner_guard)):
            raise ValueError('amended extent crossed actual rule/operative Source or basis controls')
        _digest(self.rule_source_digest);_digest(self.rule_c1_intent_digest)
        if (type(self.amendment_evidence_start) is not int or type(self.amendment_evidence_end) is not int
                or not 0<=self.amendment_evidence_start<self.amendment_evidence_end
                or type(self.amendment_evidence_text) is not str
                or len(self.amendment_evidence_text)!=self.amendment_evidence_end-self.amendment_evidence_start
                or not 1<=len(self.amendment_evidence_text.encode())<=8192):
            raise ValueError('amended extent requires its distinct actual new Source evidence span')
        if self.extent_mode=='amended' and (self.rule_source_head,self.rule_source_digest,self.rule_c1_intent_ref,self.rule_c1_intent_digest)!=(
                self.task_source_head,self.task_source_digest,self.c1_intent_ref,self.c1_intent_digest):
            raise ValueError('explicit amended rule must cite its actual new C1/Source')


def decode_artifact_task_text_extent_original_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    variants={'d08.artifact-task-text-extent-original.v1':ArtifactTaskTextExtentOriginalV1,
        'd08.artifact-task-text-extent-original.v2':ArtifactTaskTextExtentOriginalV2}
    cls=variants.get(raw.get('schema')) if type(raw) is dict else None
    if cls is None:raise ValueError('unregistered closed task text extent schema')
    return decode_typed_production_value_v1(raw,cls)


def artifact_task_text_extent_ref_v2(value):
    return 'artifact-task-text-extent-v2:'+canonical_digest((value.basis.digest,value.extent_mode,value.rule_source_head,
        value.rule_source_digest,value.rule_c1_intent_ref,value.rule_c1_intent_digest,value.evidence_start,value.evidence_end,
        value.evidence_text,value.full_extent,value.evidence_grammar,value.amendment_evidence_start,
        value.amendment_evidence_end,value.amendment_evidence_text))[:48]


def readonly_current_artifact_task_text_extent_task_v2(db,*,namespace,request,issuer):
    from .d08_personal_plan_v1 import (ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2,
        require_artifact_task_plan_revision_original_v2,artifact_task_plan_revision_operation_id_v2)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
    if type(request) is not RegisterArtifactTaskTextExtentRequestV1:raise TypeError('exact Goal extent selector required')
    goal_value=raw_head_value_v1(db,namespace,AtomKey.from_token(request.goal_ref))
    if goal_value is None:return None
    _,objective,_=_objective_basis_v1(db,namespace,request.goal_ref,_decode_goal(goal_value),issuer)
    head=db.execute('SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=? AND valid=1',
        (*namespace.as_tuple,objective['plan_ref'])).fetchone()
    if head is None:return None
    event=db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=? AND valid=1',(objective['plan_ref'],head[0])).fetchone()
    if event is None:raise MissingProductionOriginalV1('actual_current_Plan_history_for_extent_variant')
    original=read_adopted_domain_operation_v1(db,namespace,event[0])
    if original is None:raise MissingProductionOriginalV1('actual_current_Plan_W01_for_extent_variant')
    if (original['domain'],original['operation_kind'])!=('d08',ARTIFACT_TASK_PLAN_REVISION_OPERATION_V2):return None
    plan,_=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=original)
    task=decode_typed_production_value_v1(original['payload']['request']['task'],ArtifactDraftTaskSelectorV1)
    if (original['receipt'].operation_id!=artifact_task_plan_revision_operation_id_v2(task)
            or plan.goal_ref!=request.goal_ref or plan.goal_revision!=request.expected_goal_revision
            or plan.revision!=head[0] or raw_head_value_v1(db,namespace,AtomKey.from_token(objective['plan_ref']))!=plain_v1(plan)):
        raise MissingProductionOriginalV1('exact_fixed_revision_Plan_Goal_for_amended_extent')
    return task


def _read_plan_amended_artifact_task_text_extent_v2(db,*,namespace,request,task,issuer):
    from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2,require_artifact_task_plan_revision_original_v2
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    from .d11_artifact_draft_model_v1 import read_artifact_phase_selected_history_v2
    revision=read_adopted_domain_operation_v1(db,namespace,artifact_task_plan_revision_operation_id_v2(task))
    plan,_=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    p=revision['payload']['provenance']
    previous=read_current_artifact_task_milestone_v2(db,namespace=namespace,original_ref=p['previous_milestone_ref'],issuer=issuer)
    _,chosen,_=read_artifact_phase_selected_history_v2(db,selector=previous.selector,issuer=issuer)
    row=_read(db,issuer=issuer,namespace=namespace,kind=KIND,ref=chosen.binding.extent_original_ref)
    initial=decode_artifact_task_text_extent_original_v1(row[0])
    roots=tuple(dict.fromkeys((*plan.source_refs,initial.task_source_head.key.token,previous.source_head.key.token)))
    keys=(owner_grant_key(*namespace.as_tuple),AtomKey.from_token(request.goal_ref),AtomKey.from_token(task.cycle_job_ref),
        *(v.key for v in revision['read_versions']),*(v.key for v in revision['receipt'].write_versions))
    originals=(p['amendment_original_ref'],p['previous_milestone_ref'],p['task_scope_ref'],task.root_registration_ref,
        initial.objective_ref,initial.c1_intent_ref,chosen.binding.extent_original_ref,
        'd08-current:'+revision['original_digest'][:48],
        'd08-current:'+p['previous_settlement_original_digest'][:48],)
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    scope=_read(db,issuer=issuer,namespace=namespace,kind='artifact_task_scope',ref=task_scope_ref_v1(task.root_registration_ref))[0]
    return production_read_plan_v1((),keys,roots,(*originals,c1_task_intent_ref_v1(namespace,task.c02_operation_id),scope['approval_original_ref']))


# V2 only: an exact ordinary amendment clause confirms the immutable initial range.
_UNCHANGED_AMENDMENT_RANGE_V2=re.compile(
    r"(?:^|(?<=[，,；;。\n]))\s*(?P<evidence>全文仍为(?P<minimum>[1-9][0-9]{0,4})到(?P<maximum>[1-9][0-9]{0,4})字)(?=$|[，,；;。!?！?\n])")


def readonly_current_artifact_task_text_extent_basis_v2(db,*,namespace,request,issuer,bundle,owner_guard,now_utc,
        parent_budget_lease_ref,actor_ref,purpose,audiences,access_epoch,delete_epoch):
    from .artifact_task_amendment_v1 import readonly_current_artifact_task_amendment_basis_v1
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    from .d08_personal_candidate_v1 import artifact_task_choice_ids_v2
    from ..memory_types import SourceRecord
    task=readonly_current_artifact_task_text_extent_task_v2(db,namespace=namespace,request=request,issuer=issuer)
    if task is None:raise MissingProductionOriginalV1('actual_fixed_revision_before_amended_extent')
    basis=readonly_current_artifact_task_amendment_basis_v1(db,namespace=namespace,task=task,issuer=issuer,bundle=bundle,
        owner_guard=owner_guard,now_utc=now_utc,parent_budget_lease_ref=parent_budget_lease_ref,actor_ref=actor_ref,
        purpose=purpose,audiences=audiences,access_epoch=access_epoch,delete_epoch=delete_epoch)
    initial_row=_read(db,issuer=issuer,namespace=namespace,kind=KIND,ref=basis.initial_extent_ref)
    initial=decode_artifact_task_text_extent_original_v1(initial_row[0])
    intent=read_c1_task_intent_original_v1(db,namespace=namespace,c02_operation_id=task.c02_operation_id,issuer=issuer)
    source=json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
        (basis.amendment_source_head.key.token,*namespace.as_tuple)).fetchone()[0]);text=SourceRecord.from_dict(source).text
    mode='inherited';extent=initial.full_extent;start,end,evidence=initial.evidence_start,initial.evidence_end,initial.evidence_text
    rule_head,rule_digest,rule_c1,rule_c1_digest=initial.task_source_head,initial.task_source_digest,initial.c1_intent_ref,initial.c1_intent_digest
    quote=intent.intent.source_quote
    quote_start=text.find(quote)
    if quote_start<0 or text.find(quote,quote_start+1)>=0:
        raise MissingProductionOriginalV1('unique_actual_new_C1_amendment_evidence_span')
    amendment_start,amendment_end=quote_start,quote_start+len(quote)
    unchanged=tuple(_UNCHANGED_AMENDMENT_RANGE_V2.finditer(text))
    if unchanged:
        if len(unchanged)!=1 or _RANGE_RE.search(text):
            raise MissingProductionOriginalV1('single_exact_registered_unchanged_revision_range')
        confirmation=unchanged[0]
        if (int(confirmation['minimum']),int(confirmation['maximum']))!=(initial.full_extent.minimum,initial.full_extent.maximum):
            raise MissingProductionOriginalV1('revision_still_range_must_equal_actual_initial_extent')
        amendment_start=min(quote_start,confirmation.start('evidence'))
        amendment_end=max(quote_start+len(quote),confirmation.end('evidence'))
    elif _RANGE_RE.search(text):
        extent,start,end,evidence=_explicit_zh_extent_v1(text,intent.intent.source_quote)
        mode='amended';rule_head,rule_digest,rule_c1,rule_c1_digest=basis.amendment_source_head,basis.amendment_source_digest,basis.c1_intent_ref,basis.c1_intent_digest
    elif re.search(r'[0-9]+\s*(?:字|words?\b)',text,re.I):
        raise MissingProductionOriginalV1('explicit_supported_amendment_range_or_unchanged_initial_extent')
    return ArtifactTaskTextExtentOriginalV2(namespace,basis.goal_head,basis.goal_digest,basis.objective_ref,basis.objective_digest,
        basis.amendment_source_head,basis.amendment_source_digest,task.c02_operation_id,basis.c1_intent_ref,basis.c1_intent_digest,
        'd08-current:'+basis.plan_revision_original_digest[:48],basis.plan_revision_original_digest,
        artifact_task_choice_ids_v2(task,basis.plan_head)['extent'],owner_guard,start,end,evidence,extent,
        basis=basis,extent_mode=mode,rule_source_head=rule_head,rule_source_digest=rule_digest,
        rule_c1_intent_ref=rule_c1,rule_c1_intent_digest=rule_c1_digest,
        amendment_evidence_start=amendment_start,amendment_evidence_end=amendment_end,
        amendment_evidence_text=text[amendment_start:amendment_end])


def _qualified_amended_artifact_task_text_extent_v2(db,*,frame,request,readers,registration_operation_id):
    from .artifact_phase_postconditions_v1 import authorize_current_task_predecision_v2
    read=CurrentDomainReadV1(frame);read.check(db)
    value=readonly_current_artifact_task_text_extent_basis_v2(db,namespace=frame.envelope.authority.namespace,
        request=request,issuer=readers.issuer,bundle=readers.bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref,actor_ref=frame.envelope.authority.actor,
        purpose=frame.envelope.authority.purpose,audiences=frame.envelope.authority.audience,
        access_epoch=frame.envelope.version_guard.access_epoch,delete_epoch=frame.envelope.version_guard.delete_epoch)
    if value.registration_operation_id!=registration_operation_id:raise ValueError('amended extent changed its exact fixed once operation')
    plan=_read_plan_amended_artifact_task_text_extent_v2(db,namespace=value.namespace,request=request,task=value.basis.task,issuer=readers.issuer)
    for key in plan.exact_keys:read.head(db,key)
    read.source_family(db,plan.source_roots)
    for ref in plan.required_original_refs:read.original(ref)
    authorize_current_task_predecision_v2(db,frame=frame,task=value.basis.task,operation=OPERATION_KIND,
        method_ref=None,installed_readers=readers)
    return value


def require_artifact_task_text_extent_history_v2(db,*,namespace,original_ref,producing_operation_id,raw):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d08_personal_plan_v1 import require_artifact_task_plan_revision_original_v2
    from .d08_personal_candidate_v1 import artifact_task_choice_ids_v2
    value=decode_artifact_task_text_extent_original_v1(raw);basis=value.basis
    original=read_adopted_domain_operation_v1(db,namespace,producing_operation_id)
    revision=read_adopted_domain_operation_v1(db,namespace,basis.plan_revision_operation_id)
    plan,_=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    if (value.namespace!=namespace or original_ref!=artifact_task_text_extent_ref_v2(value)
            or producing_operation_id!=value.registration_operation_id
            or producing_operation_id!=artifact_task_choice_ids_v2(basis.task,basis.plan_head)['extent']
            or original is None or (original['domain'],original['operation_kind'])!=('d08',OPERATION_KIND)
            or original['payload']['coverage']!='complete' or original['payload']['provenance']!={'artifact_task_text_extent':raw}
            or original['payload']['request']!=plain_v1(RegisterArtifactTaskTextExtentRequestV1(value.goal_head.key.token,value.goal_head.revision))
            or original['payload']['owner_guard']!=plain_v1(basis.owner_guard)
            or revision['original_digest']!=basis.plan_revision_original_digest or canonical_digest(plain_v1(plan))!=basis.plan_digest
            or not revision['receipt'].commit_seq<original['receipt'].commit_seq
            or not original['payload']['now_utc']<basis.original_deadline_utc):
        raise ValueError('amended extent lost exact closed same-task W01 registration and revision predecessor')
    from .d11_life_preparation_v1 import TABLE
    saved=_artifact_receipt_sql_v1(db,'SELECT payload_json,payload_digest FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,KIND,basis.initial_extent_ref)).fetchone()
    if saved is None or saved[1]!=basis.initial_extent_digest:raise ValueError('amended extent lost immutable initial rule original')
    initial=decode_artifact_task_text_extent_original_v1(background_json_loads_v3(saved[0]))
    if value.extent_mode=='inherited' and (value.full_extent,value.rule_source_head,value.rule_source_digest,value.evidence_start,value.evidence_end,
            value.evidence_text,value.rule_c1_intent_ref,value.rule_c1_intent_digest)!=(initial.full_extent,initial.task_source_head,
            initial.task_source_digest,initial.evidence_start,initial.evidence_end,initial.evidence_text,initial.c1_intent_ref,initial.c1_intent_digest):
        raise ValueError('inherited amended extent changed actual initial rule evidence')
    source=_artifact_receipt_sql_v1(db,'SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
        (basis.amendment_source_head.key.token,basis.amendment_source_head.revision)).fetchone()
    from ..memory_types import SourceRecord
    if (source is None or source[1]!=1 or background_json_digest_v3(source[0],background_json_loads_v3(source[0]))!=basis.amendment_source_digest
            or SourceRecord.from_dict(background_json_loads_v3(source[0])).text[value.amendment_evidence_start:value.amendment_evidence_end]!=value.amendment_evidence_text):
        raise ValueError('amended extent changed its distinct immutable new Source evidence')
    return value
