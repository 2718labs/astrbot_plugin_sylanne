"""Shared values and explicit failure types for the foundation milestone."""
from dataclasses import dataclass
import hashlib
import json
import math

class EventConflict(RuntimeError):
    pass

class StaleRead(RuntimeError):
    pass

class CapacityExceeded(RuntimeError):
    pass

def nonempty(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f'{label} must be a nonempty string')

def canonical_json(value):
    """Reject Python-only values, non-string keys, cycles and nonfinite numbers."""
    active = set()
    def check(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError('JSON numbers must be finite')
            return
        if type(item) not in (list, dict):
            raise TypeError('payload must contain only JSON values')
        if id(item) in active:
            raise ValueError('cyclic JSON payload')
        active.add(id(item))
        try:
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise TypeError('JSON object keys must be strings')
                    check(child)
            else:
                for child in item: check(child)
        finally:
            active.remove(id(item))
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)

def json_object(value):
    if type(value) is not dict:
        raise TypeError('payload must be a JSON object')
    return json.loads(canonical_json(value))

@dataclass(frozen=True)
class Scope:
    bot: str
    persona: str
    session: str
    def __post_init__(self):
        for name in ('bot', 'persona', 'session'): nonempty(getattr(self, name), name)

@dataclass(frozen=True)
class AtomVersion:
    name: str
    revision: int
    def __post_init__(self):
        nonempty(self.name, 'atom name')
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError('revision must be a nonnegative integer')

@dataclass(frozen=True)
class Atom:
    name: str
    revision: int
    value: dict
    def __post_init__(self):
        AtomVersion(self.name, self.revision)
        object.__setattr__(self, 'value', json_object(self.value))

@dataclass(frozen=True)
class Snapshot:
    scope: Scope
    atoms: tuple[Atom, ...]
    def get(self, name):
        return next((atom for atom in self.atoms if atom.name == name), None)
    @property
    def versions(self):
        return tuple(AtomVersion(a.name, a.revision) for a in self.atoms)

@dataclass(frozen=True)
class Event:
    scope: Scope
    event_id: str
    occurred_at: float
    kind: str
    payload: dict
    def __post_init__(self):
        if not isinstance(self.scope, Scope): raise TypeError('scope must be Scope')
        nonempty(self.event_id, 'event_id')
        nonempty(self.kind, 'kind')
        if type(self.occurred_at) not in (int, float) or not math.isfinite(self.occurred_at):
            raise ValueError('occurred_at must be finite')
        object.__setattr__(self, 'payload', json_object(self.payload))
    @property
    def digest(self):
        body = {'scope': {'bot': self.scope.bot, 'persona': self.scope.persona, 'session': self.scope.session},
                'event_id': self.event_id, 'occurred_at': self.occurred_at, 'kind': self.kind, 'payload': self.payload}
        return hashlib.sha256(canonical_json(body).encode('utf-8')).hexdigest()

@dataclass(frozen=True)
class Write:
    name: str
    value: dict
    def __post_init__(self):
        nonempty(self.name, 'atom name')
        object.__setattr__(self, 'value', json_object(self.value))

@dataclass(frozen=True)
class Candidate:
    event: Event
    reads: tuple[AtomVersion, ...]
    writes: tuple[Write, ...]

@dataclass(frozen=True)
class CommitReceipt:
    status: str
    revisions: tuple[AtomVersion, ...]

@dataclass(frozen=True)
class StepResult:
    done: bool
    value: object = None
