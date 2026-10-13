"""D10 current continuation and immutable per-work artifact versions."""
from dataclasses import dataclass, fields

from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize, schema_hash
from ..d08.personal_plan_v1 import PLAN_TYPE, _versions

CHECKPOINT_TYPE = "d10.project_checkpoint.v1"
WORK_TYPE = "d10.project_work_version.v1"


@dataclass(frozen=True, slots=True)
class ProjectWaitConditionV1:
    producer_domain: str
    event_kind: str
    observed_versions: tuple[VersionedRef, ...]
    query_epoch: QueryEpoch
    resume_job_ref: str
    consume_cursor: int
    next_due_utc: str | None = None
    schema: str = "d10.project-wait.v1"

    def __post_init__(self):
        if (self.schema != "d10.project-wait.v1" or self.producer_domain not in {"d06", "d08", "d11"}
                or not self.event_kind or type(self.query_epoch) is not QueryEpoch
                or AtomKey.from_token(self.resume_job_ref).type_name != "runtime.job"
                or type(self.consume_cursor) is not int or self.consume_cursor < 0):
            raise ValueError("waiting requires a concrete producer, actual job and observed cursor")
        _versions(self.observed_versions, "wait watermarks")
        if self.next_due_utc is not None:
            from ..d10.offline_interval import _utc
            _utc(self.next_due_utc)


@dataclass(frozen=True, slots=True)
class ProjectTaskWaitConditionV1:
    """Wait for a new task message; contains no old job execution capability."""
    objective_ref: str
    objective_digest: str
    observed_versions: tuple[VersionedRef, ...]
    query_epoch: QueryEpoch
    consume_cursor: int
    producer_domain: str = "d06"
    event_kind: str = "artifact_task_amendment_adopted"
    schema: str = "d10.project-task-wait.v1"

    def __post_init__(self):
        if (self.schema != "d10.project-task-wait.v1"
                or (self.producer_domain,self.event_kind) != ("d06","artifact_task_amendment_adopted")
                or not self.objective_ref.startswith("artifact-task-objective:")
                or len(self.objective_digest)!=64 or any(c not in "0123456789abcdef" for c in self.objective_digest)
                or type(self.query_epoch) is not QueryEpoch
                or type(self.consume_cursor) is not int or self.consume_cursor<1):
            raise ValueError("task wait requires its immutable objective and actual consumed producer cursor")
        _versions(self.observed_versions,"task wait watermarks")


@dataclass(frozen=True, slots=True)
class ProjectCheckpointV1:
    project_ref: str
    revision: int
    plan_ref: str
    plan_revision: int
    completed_node_refs: tuple[str, ...]
    progress_refs: tuple[str, ...]
    work_version_refs: tuple[str, ...]
    next_step: str | None
    state: str
    last_fact_versions: tuple[VersionedRef, ...]
    wait_condition: ProjectWaitConditionV1 | ProjectTaskWaitConditionV1 | None = None
    schema: str = CHECKPOINT_TYPE

    def __post_init__(self):
        if (self.schema != CHECKPOINT_TYPE or AtomKey.from_token(self.project_ref).type_name != "d10.life_project.v1"
                or AtomKey.from_token(self.plan_ref).type_name != PLAN_TYPE
                or any(type(n) is not int or n < 1 for n in (self.revision, self.plan_revision))
                or self.state not in {"active", "waiting", "paused", "completed", "cancelled"}):
            raise ValueError("checkpoint requires actual project/plan revisions")
        for name, limit in (("completed_node_refs", 8), ("progress_refs", 32), ("work_version_refs", 32)):
            values = getattr(self, name)
            if (type(values) is not tuple or len(values) > limit or len(set(values)) != len(values)
                    or any(type(ref) is not str or not ref for ref in values)):
                raise ValueError("checkpoint exceeds its bounded window")
        if self.next_step is not None and (not self.next_step.startswith("task:") or self.next_step in self.completed_node_refs):
            raise ValueError("checkpoint next step must be an uncompleted adopted plan node")
        if self.state == "active" and self.next_step is None:
            raise ValueError("an active checkpoint needs its one executable next step")
        if self.state in {"completed", "cancelled"} and self.next_step is not None:
            raise ValueError("a terminal checkpoint cannot start another step")
        if (self.state == "waiting") != (type(self.wait_condition) in {ProjectWaitConditionV1,ProjectTaskWaitConditionV1}):
            raise ValueError("waiting checkpoint must retain its typed wake registration")
        _versions(self.last_fact_versions, "checkpoint facts")
        for ref in self.progress_refs:
            if AtomKey.from_token(ref).type_name != "d10.life_progress.v1":
                raise ValueError("checkpoint progress requires actual effects")
        for ref in self.work_version_refs:
            if AtomKey.from_token(ref).type_name != WORK_TYPE:
                raise ValueError("checkpoint work history requires immutable versions")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("checkpoint exceeds its metadata bound")


@dataclass(frozen=True, slots=True)
class ProjectWorkVersionV1:
    project_ref: str
    work_ref: str
    version: int
    progress_ref: str
    artifact_ref: str
    artifact_digest: str
    artifact_length: int
    terminal_ref: str
    action_outcome_ref: str
    source_refs: tuple[str, ...]
    source_versions: tuple[VersionedRef, ...]
    activity_id: str
    effect_id: str
    attempt_id: str
    node_id: str
    schema: str = WORK_TYPE

    def __post_init__(self):
        if (self.schema != WORK_TYPE or AtomKey.from_token(self.project_ref).type_name != "d10.life_project.v1"
                or AtomKey.from_token(self.progress_ref).type_name != "d10.life_progress.v1"
                or AtomKey.from_token(self.action_outcome_ref).type_name != "d08.action_outcome.v1"
                or type(self.version) is not int or self.version < 1
                or type(self.artifact_length) is not int or not 1 <= self.artifact_length <= 524288
                or len(self.artifact_digest) != 64 or any(c not in "0123456789abcdef" for c in self.artifact_digest)):
            raise ValueError("work version requires exact actual artifact/effect evidence")
        for name in ("work_ref", "artifact_ref", "terminal_ref", "activity_id", "effect_id", "attempt_id", "node_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError("work version identity is absent")
        if type(self.source_refs) is not tuple or not self.source_refs or len(set(self.source_refs)) != len(self.source_refs):
            raise ValueError("work sources must be bounded distinct originals")
        _versions(self.source_versions, "work original source versions")
        if {row.ref for row in self.source_versions} != set(self.source_refs):
            raise ValueError("work source versions must freeze the actual execution inputs")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("work version exceeds its metadata bound")


def project_checkpoint_key_v1(namespace, project_ref):
    key = AtomKey.from_token(project_ref)
    if NamespaceId.from_key(key) != namespace or key.type_name != "d10.life_project.v1":
        raise ValueError("checkpoint scope differs from its current project")
    return AtomKey(Owner("persona", *namespace.as_tuple), CHECKPOINT_TYPE,
        "project:" + canonical_digest(project_ref)[:48])


def project_work_version_key_v1(namespace, project_ref, effect_id):
    project_checkpoint_key_v1(namespace, project_ref)
    return AtomKey(Owner("persona", *namespace.as_tuple), WORK_TYPE,
        "work:" + canonical_digest((project_ref, effect_id))[:48])


def decode_project_checkpoint_type_v1(kind, value):
    cls = {CHECKPOINT_TYPE: ProjectCheckpointV1, WORK_TYPE: ProjectWorkVersionV1}[kind]
    if type(value) is not dict or set(value) != {field.name for field in fields(cls)}:
        raise ValueError("project continuation/version has unexpected fields")
    raw = dict(value)
    if cls is ProjectCheckpointV1:
        for name in ("completed_node_refs", "progress_refs", "work_version_refs"):
            raw[name] = tuple(raw[name])
        raw["last_fact_versions"] = tuple(VersionedRef(**row) for row in raw["last_fact_versions"])
        if raw["wait_condition"] is not None:
            wake = dict(raw["wait_condition"])
            wake["observed_versions"] = tuple(VersionedRef(**row) for row in wake["observed_versions"])
            epoch = dict(wake["query_epoch"])
            epoch["namespace"] = NamespaceId(**epoch["namespace"])
            wake["query_epoch"] = QueryEpoch(**epoch)
            variant={"d10.project-wait.v1":ProjectWaitConditionV1,"d10.project-task-wait.v1":ProjectTaskWaitConditionV1}
            raw["wait_condition"] = variant[wake["schema"]](**wake)
    else:
        raw["source_refs"] = tuple(raw["source_refs"])
        raw["source_versions"] = tuple(VersionedRef(**row) for row in raw["source_versions"])
    return cls(**raw)


def project_checkpoint_type_specs_v1():
    return tuple(TypeSpec(kind, ("persona",), "state",
        lambda value, kind=kind: decode_project_checkpoint_type_v1(kind, value), immutable=kind == WORK_TYPE,
        writer_domain="d10", schema_version=2 if kind==CHECKPOINT_TYPE else 1,
        schema_hash=schema_hash({"type":kind,"fields":tuple(cls.__dataclass_fields__),
            "wait_variants":("d10.project-wait.v1","d10.project-task-wait.v1")}) if kind==CHECKPOINT_TYPE
            else schema_hash({"type":kind,"fields":tuple(cls.__dataclass_fields__)}))
        for kind, cls in ((CHECKPOINT_TYPE, ProjectCheckpointV1), (WORK_TYPE, ProjectWorkVersionV1)))
