"""Private D02 metadata reader on an actual completed Authority labor Source Work."""
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from ..domains.d02 import BodyState
from ..domains.d02.character_labor_v1 import CharacterLaborPolicyV1
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import canonical_digest
from ..runtime.d01_production_operations_v1 import CurrentDomainReadV1
from ..runtime.d02_production_operations_v1 import InstalledD02ProductionReadersV1

_READERS = WeakKeyDictionary()


class InstalledAuthorityCharacterLaborBodyReadersV1:
    """Current Body/policy projections only; no Host clock or budget API."""
    def __init__(self, work, *, _issuer):
        if _issuer is not _ISSUER:
            raise TypeError("Authority labor Body readers require their private same-Work factory")
        self.work = work
        self.issuer = work.service.issuer
        self.body_quote_authority = work.service.body_authority
        _READERS[self] = (work, work.service, work.db, work.operation, work.scope,
            work.permit, work.selection_digest)

    def require_current_v1(self, *, db=None):
        from .character_labor_source_read_v1 import _actual, _READERS as source_readers
        from .character_labor_census_v1 import require_character_labor_source_census_v1
        from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        work = self.work
        if (_READERS.get(self) != (work, work.service, work.db, work.operation, work.scope,
                work.permit, work.selection_digest)
                or db is not None and db is not work.db):
            raise AuthorityUnavailable("Authority labor Body reader lost its actual Work issuance")
        _actual(work)
        reader = source_readers.get(work)
        if (reader is None or not reader.complete or reader.prepared is None
                or work.request.phase != "claim" or reader.source_material is None
                or len(reader.groups) != len(reader.metadata.plan.audiences)
                or _authority_attachment_owner_v3(work.db) is not work
                or not work.db.in_transaction):
            raise AuthorityUnavailable("Authority labor Body metadata requires completed SourceALL in its real quantum")
        meter = current_c09_sql_meter_v2()
        if meter is None:
            raise AuthorityUnavailable("Authority labor Body metadata has no actual bounded quantum")
        reader.require_current(meter)
        census = require_character_labor_source_census_v1(work, meter=meter)
        if reader.census is not census:
            raise AuthorityUnavailable("Authority labor Body reader changed its original census")
        return self

    def _current_body(self, db, read, profile_id=None):
        self.require_current_v1(db=db)
        return InstalledD02ProductionReadersV1._current_body(self, db, read, profile_id)

    def _policy(self, read, row):
        self.require_current_v1()
        policy, original = InstalledD02ProductionReadersV1._policy(self, read, row)
        if type(policy) is not CharacterLaborPolicyV1:
            raise AuthorityUnavailable("Authority labor Body reader cannot select a different D02 policy family")
        return policy, original

    def require_labor_census_v1(self, db, read, state):
        self.require_current_v1(db=db)
        from .character_labor_source_read_v1 import _READERS as source_readers
        if type(read) is not CurrentDomainReadV1 or type(state) is not BodyState:
            raise TypeError("Authority labor census requires its real current D02 frame and Body state")
        read.check(db)
        work = self.work
        source = source_readers[work]
        frame, ns = read.frame, work.namespace
        binding = source.metadata.binding
        if (frame.envelope.authority.namespace != ns
                or frame.envelope.identity.operation_id != binding.prepare_operation_id
                or source.prepared.binding != binding
                or frame.owner_guard.grant_ref != binding.owner_grant_ref
                or frame.owner_guard.grant_revision != binding.owner_grant_revision
                or frame.owner_guard.grant_digest != binding.owner_grant_digest):
            raise AuthorityUnavailable("Authority D02 frame left its actual prepared binding/current Owner")
        census = source.census
        guard = frame.envelope.version_guard
        if census.graph_stamp != (frame.snapshot.epochs[0].revision, guard.access_epoch, guard.delete_epoch):
            raise AuthorityUnavailable("Authority labor census Graph/Source/deletion stamp changed")
        key = AtomKey(Owner("persona", *ns.as_tuple), "d02.body_state.v1", state.profile_id)
        atom = read.head(db, key, required=True)
        if (not atom.valid or census.body_state.ref != key.token
                or census.body_state.version != atom.revision or atom.revision != state.version
                or census.body_state_value_digest != canonical_digest(atom.value)
                or BodyState(**atom.value) != state or census.body_state_cursor != state.cursor):
            raise AuthorityUnavailable("Authority labor census no longer describes the actual current Body")
        return census


_ISSUER = object()


def create_authority_character_labor_body_readers_v1(work):
    reader = InstalledAuthorityCharacterLaborBodyReadersV1(work, _issuer=_ISSUER)
    try:
        return reader.require_current_v1(db=work.db)
    except BaseException:
        _READERS.pop(reader, None)
        raise


def require_authority_character_labor_body_readers_v1(reader, *, issuer, body_quote_authority, db=None):
    if (type(reader) is not InstalledAuthorityCharacterLaborBodyReadersV1
            or reader.issuer is not issuer or reader.body_quote_authority is not body_quote_authority):
        raise TypeError("actual same-issuer Authority labor Body reader required")
    return reader.require_current_v1(db=db)


def release_authority_character_labor_body_readers_v1(work):
    for reader in tuple(_READERS):
        if reader.work is work:
            _READERS.pop(reader)
