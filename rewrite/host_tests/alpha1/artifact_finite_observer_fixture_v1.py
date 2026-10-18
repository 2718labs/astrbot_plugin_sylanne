"""Historical finite engineering observer cases; excluded from installed runtime."""
from dataclasses import dataclass,fields
import hashlib,json
from sylanne3.runtime.artifact_phase_postconditions_v1 import _digest,_text,STATUSES

@dataclass(frozen=True,slots=True)
class ArtifactPhaseFixtureObserverCaseV1:
    task_source_text_digest: str
    phase_kind: str
    condition_id: str
    content_digest: str
    status: str
    evidence_literals: tuple[str,...]

    def __post_init__(self):
        _digest(self.task_source_text_digest);_digest(self.content_digest)
        if (self.phase_kind not in {'sample_check','check'} or self.condition_id not in {'tone','task_semantics'}
                or self.status not in STATUSES or type(self.evidence_literals) is not tuple
                or len(self.evidence_literals)>16):
            raise ValueError('finite observer case has another actual task/phase/condition scope')
        for literal in self.evidence_literals:_text(literal)


@dataclass(frozen=True,slots=True)
class ArtifactPhaseFixtureObserverV1:
    observer_id: str
    observer_version: int
    asset_ref: str
    asset_digest: str
    cases: tuple[ArtifactPhaseFixtureObserverCaseV1,...]
    source_scope: str='LOCAL_FIXTURE'

    def __post_init__(self):
        _text(self.observer_id);_text(self.asset_ref);_digest(self.asset_digest)
        if (type(self.observer_version) is not int or self.observer_version<1 or self.source_scope!='LOCAL_FIXTURE'
                or not self.asset_ref.startswith('/') or type(self.cases) is not tuple or not 1<=len(self.cases)<=128
                or any(type(case) is not ArtifactPhaseFixtureObserverCaseV1 for case in self.cases)
                or len({(c.task_source_text_digest,c.phase_kind,c.condition_id,c.content_digest) for c in self.cases})!=len(self.cases)):
            raise ValueError('finite observer is a protected installed finite fixture asset')


def artifact_phase_fixture_observer_from_asset_v1(*,asset_ref,asset_bytes,expected_digest):
    if type(asset_bytes) is not bytes or len(asset_bytes)>131072 or hashlib.sha256(asset_bytes).hexdigest()!=expected_digest:
        raise ValueError('finite observer asset bytes differ from actual protected pin')
    raw=json.loads(asset_bytes)
    if (type(raw) is not dict or set(raw)!={'schema','observer_id','observer_version','source_scope','cases'}
            or raw['schema']!='d11.artifact-phase-finite-observer-rules.v1' or type(raw['cases']) is not list):
        raise ValueError('finite observer asset has another closed schema')
    cases=[]
    for row in raw['cases']:
        if type(row) is not dict or set(row)!={f.name for f in fields(ArtifactPhaseFixtureObserverCaseV1)} or type(row['evidence_literals']) is not list:
            raise ValueError('finite observer case has another closed schema')
        cases.append(ArtifactPhaseFixtureObserverCaseV1(**{**row,'evidence_literals':tuple(row['evidence_literals'])}))
    return ArtifactPhaseFixtureObserverV1(raw['observer_id'],raw['observer_version'],asset_ref,expected_digest,tuple(cases),raw['source_scope'])

