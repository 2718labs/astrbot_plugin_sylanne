"""Registered D05 catalogue conversion on the existing Graph connection.

Only the installed Authority maintenance adapter may open this path.  Normal
GraphStore catalogue checks are unchanged.  Current heads gain revisions;
prior history, signed originals, effect identities and budget rows are never
rewritten.  The cursor and each batch's changes commit in the same transaction.
"""
from dataclasses import dataclass, replace
import hashlib
import json

from ..contracts import EventConflict, StaleRead
from ..graph_types import AtomKey, TypeRegistry
from ..runtime_contracts import canonical_serialize as canonical_json


MIGRATION_ID = "d05.catalogue-upgrade.v2"
CHANGED_TYPES = frozenset({"d05.contribution", "d05.relationship_projection"})
OLD_CONTRIBUTION_HASH = "9a7d37b33cf5314cfbb3415987fcc6c723b120be5cf0e0e9355dba828a08f9b7"
TARGET_D05_HASHES = {
    "d05.contribution": "6ab001020c03aa0679826f772bf972acb1df74366408b4e4f83718dc844a98e8",
    "d05.relationship_projection": "c3c832fd4ae7b3b6ca165893ad5ddc88f7610afc98a9493481ea064c3bd0536d",
}
# Exact append-only registrations shipped with this migration. Existing rows of
# these types would mean the input is not one of the two pinned source Graphs.
APPENDED_TYPES = {
    "d08.decision_record.v2": (("activity",), "state", True, 2, "d08", "a47a16b8cd9fb8e5b6f62af2815a636457265a3578c9697525bfdfd98b2736a0"),
    "d08.personal_plan.v1": (("activity",), "state", False, 1, "d08", "8599ac8e301c2ad6d4c4a50ebcdfe84a5af7d9dd80d59076372665a19920b85a"),
    "d09.natural_verified_segment_batch.v3": (("activity",), "state", True, 3, "d09", "79841de4e42420ac2fd6246b47df3d5c845ff655b3065eb34435ddb305f4e5ae"),
    "d10.project_checkpoint.v1": (("persona",), "state", False, 1, "d10", "be0d723c777317669ba5b647488925f4a0dfcabad47a4b8a1c252bbee488564e"),
    "d10.project_work_version.v1": (("persona",), "state", True, 1, "d10", "2626869527a0096b013077a394cbc9bb5970f2a3b4caf41aa7f8dfacc787989f"),
    "d11.draft_artifact.v1": (("activity",), "state", True, 1, "d11", "d6541eb0e0b1230dacec495f55e6cc2832232d1c94380def4ec5759a698346d3"),
    "d11.draft_segment_end.v1": (("activity",), "state", True, 1, "d11", "7d1ae67f6430ca44306a479b02a6da2cb7cdb99a5dfac256a728538a0a2bc6bb"),
    "d11.draft_segment_start.v1": (("activity",), "state", True, 1, "d11", "482e4e7434f4bb2b88cc550c9845fbbefff3533e1a4f3439b1a7777cbba50483"),
}


@dataclass(frozen=True, slots=True)
class RegisteredCatalogueSourceV1:
    catalogue_hash: str
    package_zip_sha256: str
    projection_schema_hash: str


SOURCES = (
    RegisteredCatalogueSourceV1(
        "6a05fc901a3c45696faaab63746a6bf795db79282c6be7fdc8bffb6c228a71d1",
        "706fc6d631a9f8ee6e3b085936fd25a48135c0f3c971e2c80962dfe8169f8f4a",
        "98add007e49c437907f19426d60004530863bd7858021763c0f797d00d0e2d7a"),
    RegisteredCatalogueSourceV1(
        "fb3c44ee4ce9bf85325bb445b891144929aea14d6d7d722f6004d4df817f4f8f",
        "46dd05a2b4d3269b8b435035bbeb6c74b23687037d7ad19379eaf147787b49ba",
        "189f582b13f6be983f0a13e89ac2f191bbdc2a9c70dbf2623bed8b64852eeccf"),
)

@dataclass(frozen=True, slots=True)
class RegisteredCatalogueTargetV1:
    catalogue_hash: str
    type_count: int
    appended_types: tuple[tuple[str, tuple], ...]
    translator: str


# Immutable, explicit target contracts. The original APPENDED_TYPES/SOURCES
# remain the historical contract and never follow resources/current.json.
TARGET_LEGACY_V1 = RegisteredCatalogueTargetV1('d92b93e5d114f8d74168e7430ed06559b39199dbaba9bbd590fd31a5c9bcd1d8', 144, tuple(sorted(APPENDED_TYPES.items())), "d05.current-heads.v2")
TARGET_145_V1 = RegisteredCatalogueTargetV1("c2d06c01dbbd6f9a7fe4e5483e061fcbffd7033bc799fb6459bd23861b79753c", 145, (('d06.artifact_task_amendment.v1', (('activity',), 'state', True, 1, 'd06', 'bdb5c263bef4db2ad664a7cfeb1d96ea7bc998eccd02da54ae6e1819bde1f06c')), ('d08.decision_record.v2', (('activity',), 'state', True, 2, 'd08', 'a47a16b8cd9fb8e5b6f62af2815a636457265a3578c9697525bfdfd98b2736a0')), ('d08.personal_plan.v1', (('activity',), 'state', False, 1, 'd08', '0fd8a818df116681f662f8e425fae83be7d1bc70095d1272fc277e8e9958c031')), ('d09.natural_verified_segment_batch.v3', (('activity',), 'state', True, 3, 'd09', '79841de4e42420ac2fd6246b47df3d5c845ff655b3065eb34435ddb305f4e5ae')), ('d10.project_checkpoint.v1', (('persona',), 'state', False, 2, 'd10', '216b74b660e0f51c7ba3f39c2902b6ab26a8cedfe03da8a7f106901cc859f592')), ('d10.project_work_version.v1', (('persona',), 'state', True, 1, 'd10', '2626869527a0096b013077a394cbc9bb5970f2a3b4caf41aa7f8dfacc787989f')), ('d11.draft_artifact.v1', (('activity',), 'state', True, 1, 'd11', 'd6541eb0e0b1230dacec495f55e6cc2832232d1c94380def4ec5759a698346d3')), ('d11.draft_segment_end.v1', (('activity',), 'state', True, 1, 'd11', '7d1ae67f6430ca44306a479b02a6da2cb7cdb99a5dfac256a728538a0a2bc6bb')), ('d11.draft_segment_start.v1', (('activity',), 'state', True, 1, 'd11', '482e4e7434f4bb2b88cc550c9845fbbefff3533e1a4f3439b1a7777cbba50483'))), "d05.current-heads.v2")
TARGET_158_V1 = RegisteredCatalogueTargetV1("273b33a7a6d75250c4dcf0f5e15b25ec0dcab45dcd4e09f6cd136ba1b34fbdf1", 158, TARGET_145_V1.appended_types + (('d01.method_evaluation.v1', (('persona',), 'state', True, 1, 'd01', 'bb31697cdbfcceed76d2afd68bd51000f2b500fc11bbf5e1c46050719ac4e937')), ('d01.method_evaluation_protocol.v1', (('persona',), 'state', True, 1, 'd01', '6a3f5983fbb3cb518147823be4e42b7c66514e6cb8bb28465cb184d6dad5dd91')), ('d01.method_experiment_plan.v1', (('persona',), 'state', True, 1, 'd01', 'b935463c5f69b6b35c09a3e216031500361ca218b84748170ddc6cdd41b49803')), ('d01.method_outcome_review.v1', (('persona',), 'state', True, 1, 'd01', '6c9be0707b140e2fe13fcfcc4433b8e80ba70202f529cfd04e3575034b62fe21')), ('d01.method_scoped_trial.v1', (('persona',), 'state', False, 1, 'd01', '27ff0d4e212896d435118a96cba96e0f28937f65cc0b6d53dea819801babc932')), ('d05.dimension_estimate.v2', (('relation',), 'state', False, 2, 'd05', 'f52635e13ba36c24bfbc2c6af03b68cb23d06835fe628d62faae34ce8d8b83d9')), ('d05.interaction_contribution.v3', (('relation',), 'state', False, 3, 'd05', '81ea1e5083cb9669700021c27bead9fde56155564e371a1dbdb658a92cbd29b2')), ('d05.reciprocity_pattern.v2', (('relation',), 'state', False, 2, 'd05', '8ce52a2aab5ad2d1113327e989e9c99789f9c7d3f2e598b19c0888be1b1e0f1e')), ('d05.relationship_checkpoint.v2', (('relation',), 'state', True, 2, 'd05', '285485ab7a68a6398c0b3477439e2d04e18d15d4283aedcbc32e131480a50783')), ('d05.relationship_expectation.v2', (('relation',), 'state', False, 2, 'd05', '7838299728fc8a0b722648f69d271f0688416dbb8cc01163d9de638b7b1d173c')), ('d05.relationship_profile.v2', (('relation',), 'state', False, 2, 'd05', '48abd1f05547381f77b0593034b5d11e364eb4bc6e0de3412de16bf26ee0e5a9')), ('d05.repair_process.v2', (('relation',), 'state', False, 2, 'd05', 'b693887ce8c4fffb62518cbb968cc09a9486c2f38557f1d0b4268186d1c94027')), ('d09.natural_batch_disposition.v1', (('activity',), 'state', False, 1, 'd09', '346484c8bab8884ebf664e9957b5df3070f77625162c5e9ee8998f0f43dc90cd'))), "d05.current-heads.v2")
TARGET_145_TO_158_V1 = RegisteredCatalogueTargetV1(TARGET_158_V1.catalogue_hash, 158, (('d01.method_evaluation.v1', (('persona',), 'state', True, 1, 'd01', 'bb31697cdbfcceed76d2afd68bd51000f2b500fc11bbf5e1c46050719ac4e937')), ('d01.method_evaluation_protocol.v1', (('persona',), 'state', True, 1, 'd01', '6a3f5983fbb3cb518147823be4e42b7c66514e6cb8bb28465cb184d6dad5dd91')), ('d01.method_experiment_plan.v1', (('persona',), 'state', True, 1, 'd01', 'b935463c5f69b6b35c09a3e216031500361ca218b84748170ddc6cdd41b49803')), ('d01.method_outcome_review.v1', (('persona',), 'state', True, 1, 'd01', '6c9be0707b140e2fe13fcfcc4433b8e80ba70202f529cfd04e3575034b62fe21')), ('d01.method_scoped_trial.v1', (('persona',), 'state', False, 1, 'd01', '27ff0d4e212896d435118a96cba96e0f28937f65cc0b6d53dea819801babc932')), ('d05.dimension_estimate.v2', (('relation',), 'state', False, 2, 'd05', 'f52635e13ba36c24bfbc2c6af03b68cb23d06835fe628d62faae34ce8d8b83d9')), ('d05.interaction_contribution.v3', (('relation',), 'state', False, 3, 'd05', '81ea1e5083cb9669700021c27bead9fde56155564e371a1dbdb658a92cbd29b2')), ('d05.reciprocity_pattern.v2', (('relation',), 'state', False, 2, 'd05', '8ce52a2aab5ad2d1113327e989e9c99789f9c7d3f2e598b19c0888be1b1e0f1e')), ('d05.relationship_checkpoint.v2', (('relation',), 'state', True, 2, 'd05', '285485ab7a68a6398c0b3477439e2d04e18d15d4283aedcbc32e131480a50783')), ('d05.relationship_expectation.v2', (('relation',), 'state', False, 2, 'd05', '7838299728fc8a0b722648f69d271f0688416dbb8cc01163d9de638b7b1d173c')), ('d05.relationship_profile.v2', (('relation',), 'state', False, 2, 'd05', '48abd1f05547381f77b0593034b5d11e364eb4bc6e0de3412de16bf26ee0e5a9')), ('d05.repair_process.v2', (('relation',), 'state', False, 2, 'd05', 'b693887ce8c4fffb62518cbb968cc09a9486c2f38557f1d0b4268186d1c94027')), ('d09.natural_batch_disposition.v1', (('activity',), 'state', False, 1, 'd09', '346484c8bab8884ebf664e9957b5df3070f77625162c5e9ee8998f0f43dc90cd'))), "append-only.v1")


# Exact 163-row export; 158 remains an immutable target, never an unpinned source.
_TARGET_163_ADDITIONS_V1 = (('d01.method_blind_review_request.v2', (('persona',), 'state', True, 2, 'd01', 'b24ce8f2eacb9b2724e5c383168709f7d8e3bd9ea4d658e6ba9b3814c6334347')), ('d01.method_trial_proposal.v2', (('persona',), 'state', True, 2, 'd01', '8f8080c97568c7cea7a140ce82ef51b1d9750834bf55642c1337c1d2f90f00c8')), ('d11.contact_p2_qualification.v1', (('activity',), 'state', True, 1, 'd11', 'a8025aedc92908b1a7454283737c06c3f405afe747c06aaecd75372e085a7ec6')), ('d13.derived_block_metadata.v1', (('persona',), 'cache', False, 1, 'd13', 'a7d71e010017642722df968da859f1a7248bcfccabc927aac16448046c0bc3b2')), ('runtime.contact_platform_observation.v1', (('activity',), 'state', True, 1, 'd11', 'a507868090cfc83fbc5ed572dfcd7dd8df1047d4d90621b3394a421d607de9c4')))
TARGET_163_V1 = RegisteredCatalogueTargetV1("2b879cb8cbfc4f3bded9226829e6cec14b281f364a992e9616baa21f4ad4d5c1", 163, TARGET_158_V1.appended_types + _TARGET_163_ADDITIONS_V1, "d05.current-heads.v2")
TARGET_145_TO_163_V1 = RegisteredCatalogueTargetV1(TARGET_163_V1.catalogue_hash, 163, TARGET_145_TO_158_V1.appended_types + _TARGET_163_ADDITIONS_V1, "append-only.v1")

# Independent V2 adds the exact turn closure; historical 163 targets stay immutable.
_TARGET_164_ADDITIONS_V1 = _TARGET_163_ADDITIONS_V1 + (
    ('d13.derived_block_metadata.v2', (('persona',), 'cache', False, 2, 'd13', '35d6fcee3759bcbb1eeb330f40a24e0199bf55e3ee61ae46a4a819926aa8ac08')),)
TARGET_164_V1 = RegisteredCatalogueTargetV1(
    "83c77457ddc14172d006f34e89e31bef4acb69d84596f4f70c1e35e683addabb", 164,
    TARGET_158_V1.appended_types + _TARGET_164_ADDITIONS_V1, "d05.current-heads.v2")
TARGET_145_TO_164_V1 = RegisteredCatalogueTargetV1(
    TARGET_164_V1.catalogue_hash, 164,
    TARGET_145_TO_158_V1.appended_types + _TARGET_164_ADDITIONS_V1, "append-only.v1")


def registered_target_v1(source_hash, target_hash):
    if source_hash in {source.catalogue_hash for source in SOURCES}:
        for target in (TARGET_LEGACY_V1, TARGET_145_V1, TARGET_158_V1, TARGET_163_V1, TARGET_164_V1):
            if target.catalogue_hash == target_hash:
                return target
    if source_hash == TARGET_145_V1.catalogue_hash:
        for target in (TARGET_145_TO_158_V1, TARGET_145_TO_163_V1, TARGET_145_TO_164_V1):
            if target.catalogue_hash == target_hash:
                return target
    raise ValueError("unregistered exact source/target catalogue conversion contract")

# Actual frozen candidate-36 installation package, independently matched to
# its archived 145-row catalogue. This adds no intermediate source authority.
APPEND_ONLY_SOURCES = (RegisteredCatalogueSourceV1(
    "c2d06c01dbbd6f9a7fe4e5483e061fcbffd7033bc799fb6459bd23861b79753c",
    "bd22ad6b6ceb162d3fd01390f7a2ec7f194b776ac24cf5ce96af9047bae23380",
    "c3c832fd4ae7b3b6ca165893ad5ddc88f7610afc98a9493481ea064c3bd0536d"),)

OPERATIONS = "graph_catalogue_upgrades_v1"
BATCHES = "graph_catalogue_upgrade_batches_v1"
FRONTIER = "graph_catalogue_upgrade_frontier_v1"
DDL = {
    OPERATIONS: f"CREATE TABLE {OPERATIONS}(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,source_catalogue_hash TEXT NOT NULL,target_catalogue_hash TEXT NOT NULL,source_package_sha256 TEXT NOT NULL,target_manifest_digest TEXT NOT NULL,phase TEXT NOT NULL,cursor TEXT NOT NULL,batch_index INTEGER NOT NULL,converted_rows INTEGER NOT NULL,unresolved_rows INTEGER NOT NULL,initial_requirements_json TEXT NOT NULL,expected_graph_revision INTEGER NOT NULL,started_at REAL NOT NULL,completion_json TEXT,PRIMARY KEY(bot,persona,operation_id))",
    BATCHES: f"CREATE TABLE {BATCHES}(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,batch_index INTEGER NOT NULL,phase TEXT NOT NULL,cursor_before TEXT NOT NULL,cursor_after TEXT NOT NULL,input_digest TEXT NOT NULL,receipt_json TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id,batch_index))",
    FRONTIER: f"CREATE TABLE {FRONTIER}(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,token TEXT NOT NULL,edge_cursor TEXT NOT NULL,done INTEGER NOT NULL CHECK(done IN (0,1)),PRIMARY KEY(bot,persona,operation_id,token))",
}
MAX_BATCH_ROWS = 32
MAX_BATCH_BYTES = 262144
COLUMNS = {
    OPERATIONS: ('bot','persona','operation_id','request_digest','source_catalogue_hash','target_catalogue_hash',
        'source_package_sha256','target_manifest_digest','phase','cursor','batch_index','converted_rows',
        'unresolved_rows','initial_requirements_json','expected_graph_revision','started_at','completion_json'),
    BATCHES: ('bot','persona','operation_id','batch_index','phase','cursor_before','cursor_after','input_digest','receipt_json'),
    FRONTIER: ('bot','persona','operation_id','token','edge_cursor','done'),
}
RETAINED_RECEIPT = 'sylanne.graph-catalogue-upgrade-retained-receipt.v1'
RETAINED_REQUIREMENTS = 'sylanne.graph-catalogue-upgrade-retained-requirements.v1'
RETIRED_TOKEN_PREFIX = 'catalogue-token-sha256:'
_RECEIPT_FIELDS = frozenset(('schema','migration_id','operation_id','namespace','source_catalogue_hash',
    'target_catalogue_hash','target_manifest_digest','batch_index','phase','cursor','converted_rows',
    'unresolved_rows','graph_epoch','graph_revision','coverage_gaps'))


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('catalogue original digest differs')
    return value


def _number(value):
    if type(value) is not int or value < 0:
        raise ValueError('catalogue original count differs')
    return value


def _json(raw):
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError('catalogue original is not canonical JSON')
    return value


def _token(value, namespace, *, empty=True, retired=False):
    if empty and value == '':
        return None
    if retired and type(value) is str and value.startswith(RETIRED_TOKEN_PREFIX):
        _sha(value.removeprefix(RETIRED_TOKEN_PREFIX))
        return None
    key = AtomKey.from_token(value)
    if (key.owner.bot, key.owner.persona) != tuple(namespace):
        raise ValueError('catalogue original token crosses namespace')
    return key


def decode_catalogue_receipt_v1(raw, *, namespace, operation_id):
    """Closed ordinary or C09-retained receipt, never a current permission."""
    value = _json(raw)
    if type(value) is not dict:
        raise ValueError('catalogue receipt object required')
    if value.get('schema') == RETAINED_RECEIPT:
        if set(value) != {'schema','operation_id','batch_index','original_receipt_digest'}:
            raise ValueError('retained catalogue receipt shape differs')
        if value['operation_id'] != operation_id:
            raise ValueError('retained catalogue receipt operation differs')
        _number(value['batch_index']); _sha(value['original_receipt_digest'])
        return value
    if (set(value) != _RECEIPT_FIELDS or value['schema'] != 'sylanne.graph-catalogue-upgrade-receipt.v1'
            or value['migration_id'] != MIGRATION_ID or value['operation_id'] != operation_id
            or value['namespace'] != list(namespace) or value['phase'] not in {'convert','invalidate','verify','completed'}):
        raise ValueError('catalogue receipt shape/scope differs')
    registered_source_v1(value['source_catalogue_hash'])
    registered_target_v1(value['source_catalogue_hash'], value['target_catalogue_hash'])
    for name in ('target_catalogue_hash','target_manifest_digest'):
        _sha(value[name])
    for name in ('batch_index','converted_rows','unresolved_rows','graph_epoch','graph_revision'):
        _number(value[name])
    if (value['unresolved_rows'] > value['converted_rows']
            or value['graph_revision'] <= value['batch_index'] or value['graph_epoch'] <= value['batch_index']):
        raise ValueError('catalogue receipt counters differ')
    _token(value['cursor'], namespace)
    if type(value['coverage_gaps']) is not list or len(value['coverage_gaps']) > 64:
        raise ValueError('catalogue receipt gap inventory differs')
    for gap in value['coverage_gaps']:
        if type(gap) is not list or len(gap) != 2 or gap[1] not in {
                'legacy_unresolved_missing_committed_recollection_original',
                'unregistered_legacy_relationship_state', 'legacy_unresolved_relationship_history'}:
            raise ValueError('catalogue receipt has an unregistered gap')
        _token(gap[0], namespace, empty=False)
    return value


def validate_catalogue_upgrade_schema_v1(db):
    present = {name for name in DDL if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()}
    if present and present != set(DDL):
        raise ValueError('catalogue upgrade technical table family is incomplete')
    for name in present:
        if (db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() != (DDL[name],)
                or tuple(row[1] for row in db.execute('PRAGMA table_info('+name+')')) != COLUMNS[name]):
            raise ValueError('catalogue upgrade technical table schema differs')
    return bool(present)


def validate_catalogue_upgrade_row_v1(table, columns, row):
    if columns != COLUMNS.get(table) or len(row) != len(columns):
        raise ValueError('catalogue upgrade row columns differ')
    from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2
    from uuid import UUID
    namespace = NamespaceId(*row[:2])
    operation = UUID(row[2])
    if operation.version != 4 or str(operation) != row[2]:
        raise ValueError('catalogue operation identity absent')
    if table == OPERATIONS:
        for index in (3,4,5,6,7): _sha(row[index])
        registered_target_v1(row[4], row[5])
        if registered_source_v1(row[4]).package_zip_sha256 != row[6] or row[8] not in {'convert','invalidate','verify','completed'}:
            raise ValueError('catalogue registered source/phase differs')
        _token(row[9], namespace.as_tuple)
        for index in (10,11,12,14): _number(row[index])
        if row[12] > row[11]:
            raise ValueError('catalogue unresolved total exceeds converted heads')
        import math
        if type(row[15]) not in (int,float) or not math.isfinite(row[15]) or row[15] < 0:
            raise ValueError('catalogue start timestamp differs')
        original = _json(row[13])
        if original.get('schema') == RETAINED_REQUIREMENTS:
            if set(original) != {'schema','original_requirements_digest'} or row[8] != 'completed':
                raise ValueError('retained catalogue requirements shape differs')
            _sha(original['original_requirements_digest'])
        else:
            if set(original) != set(SnapshotRequirementsV2.__dataclass_fields__):
                raise ValueError('catalogue original recovery fields differ')
            original['namespace'] = NamespaceId(**original['namespace'])
            if SnapshotRequirementsV2(**original).namespace != namespace:
                raise ValueError('catalogue original recovery namespace differs')
        if (row[8] == 'completed') != (row[16] is not None):
            raise ValueError('catalogue completion presence differs')
        if row[16] is not None:
            receipt = decode_catalogue_receipt_v1(row[16], namespace=namespace.as_tuple, operation_id=row[2])
            if receipt['batch_index'] != row[10] - 1:
                raise ValueError('catalogue completion batch differs')
            if receipt['schema'] != RETAINED_RECEIPT and (
                    receipt['phase'] != 'completed' or receipt['source_catalogue_hash'] != row[4]
                    or receipt['target_catalogue_hash'] != row[5] or receipt['target_manifest_digest'] != row[7]
                    or (receipt['converted_rows'],receipt['unresolved_rows'],receipt['graph_revision']) != (row[11],row[12],row[14])):
                raise ValueError('catalogue completion totals differ')
    elif table == BATCHES:
        _number(row[3]); _sha(row[7])
        if row[4] not in {'convert','invalidate','verify'}:
            raise ValueError('catalogue batch phase differs')
        _token(row[5], namespace.as_tuple); _token(row[6], namespace.as_tuple)
        receipt = decode_catalogue_receipt_v1(row[8], namespace=namespace.as_tuple, operation_id=row[2])
        if receipt['batch_index'] != row[3] or receipt['schema'] != RETAINED_RECEIPT and receipt['cursor'] != row[6]:
            raise ValueError('catalogue batch cursor/receipt differs')
        if receipt['schema'] != RETAINED_RECEIPT and receipt['phase'] not in {
                'convert': ({'verify'} if registered_target_v1(receipt['source_catalogue_hash'], receipt['target_catalogue_hash']).translator == 'append-only.v1'
                    else {'convert','invalidate'}), 'invalidate': {'invalidate','verify'},
                'verify': {'verify','completed'}}[row[4]]:
            raise ValueError('catalogue batch phase transition differs')
    else:
        _token(row[3], namespace.as_tuple, empty=False, retired=True)
        _token(row[4], namespace.as_tuple)
        if type(row[5]) is not int or row[5] not in (0,1):
            raise ValueError('catalogue frontier state differs')
        if row[3].startswith(RETIRED_TOKEN_PREFIX) and (row[4] != '' or row[5] != 1):
            raise ValueError('retained catalogue frontier cannot run')
    return namespace


def catalogue_upgrade_c09_rows_v1(db, *, affected, affected_operations=()):
    """Classify the whole closed family, using each actual Graph event read set.

    Pending conversion blocks C09. Completed affected operations lose their
    cursors and gap bodies; operation/digest and hashed token identities remain.
    Signed domain originals and Graph event commitments are owned by their
    existing C09 codecs and are never rewritten here.
    """
    if not validate_catalogue_upgrade_schema_v1(db):
        return {}
    rows = {name: tuple(db.execute('SELECT * FROM '+name)) for name in DDL}
    operations = {}
    for table, items in rows.items():
        for row in items:
            validate_catalogue_upgrade_row_v1(table, COLUMNS[table], row)
            if table == OPERATIONS:
                if row[8] != 'completed':
                    raise ValueError('C09 cannot cross a pending catalogue upgrade')
                operations[row[:3]] = row
    hits, batches = set(), {}
    affected = set(affected)
    for row in rows[BATCHES]:
        key = row[:3]; operation = operations.get(key)
        if operation is None:
            raise ValueError('catalogue batch has no completed original')
        batches.setdefault(key, []).append(row)
        receipt = decode_catalogue_receipt_v1(row[8], namespace=row[:2], operation_id=row[2])
        event = db.execute('SELECT digest,reads,revisions,invalidated,epoch_revision FROM graph_events '
            'WHERE bot=? AND persona=? AND session=? AND event_id=?',
            (*row[:2], MIGRATION_ID, row[2]+':'+str(row[3]))).fetchone()
        if event is None or event[0] != row[7]:
            raise ValueError('catalogue batch lost its committed Graph event')
        material = [_json(cell) for cell in event[1:4]]
        for versions in material:
            if type(versions) is not list:
                raise ValueError('catalogue event versions differ')
            for version in versions:
                if type(version) is not list or len(version) != 2:
                    raise ValueError('catalogue event version shape differs')
                _token(version[0], row[:2], empty=False); _number(version[1])
        if receipt['schema'] != RETAINED_RECEIPT:
            if (receipt['source_catalogue_hash'],receipt['target_catalogue_hash'],receipt['target_manifest_digest']) != (operation[4],operation[5],operation[7]):
                raise ValueError('catalogue batch target differs from its operation')
            if (event[4] != receipt['graph_epoch'] or row[7] != _digest(
                    [operation[3],row[4],row[5],row[3],*material,receipt['coverage_gaps']])):
                raise ValueError('catalogue batch audit commitment differs')
        references = {item[0] for values in material for item in values} | {row[5],row[6]}
        if receipt['schema'] != RETAINED_RECEIPT:
            references.update(item[0] for item in receipt['coverage_gaps'])
        if references & affected or row[2] in affected_operations:
            hits.add(key)
    for key, operation in operations.items():
        actual = sorted(batches.get(key, ()), key=lambda row: row[3])
        if (tuple(row[3] for row in actual) != tuple(range(operation[10])) or not actual
                or actual[-1][8] != operation[16]):
            raise ValueError('catalogue operation batch closure differs')
        if operation[9] in affected or operation[2] in affected_operations:
            hits.add(key)
    for row in rows[FRONTIER]:
        if row[:3] not in operations or row[5] != 1:
            raise ValueError('catalogue frontier is not a completed drained original')
        if row[3] in affected or row[4] in affected:
            hits.add(row[:3])
    output = {}
    for table, items in rows.items():
        classified = []
        for row in items:
            updated = list(row)
            if row[:3] in hits:
                if table == OPERATIONS:
                    updated[9] = ''
                    raw = _json(row[13])
                    if raw.get('schema') != RETAINED_REQUIREMENTS:
                        updated[13] = canonical_json(dict(schema=RETAINED_REQUIREMENTS, original_requirements_digest=_digest(raw)))
                    receipt_index = 16
                elif table == BATCHES:
                    updated[5] = updated[6] = ''
                    receipt_index = 8
                else:
                    if not row[3].startswith(RETIRED_TOKEN_PREFIX):
                        updated[3] = RETIRED_TOKEN_PREFIX + _digest(row[3])
                    updated[4] = ''
                    receipt_index = None
                if receipt_index is not None:
                    raw = _json(row[receipt_index])
                    if raw.get('schema') != RETAINED_RECEIPT:
                        updated[receipt_index] = canonical_json(dict(schema=RETAINED_RECEIPT,
                            operation_id=row[2], batch_index=raw['batch_index'], original_receipt_digest=_digest(raw)))
            updated = tuple(updated)
            validate_catalogue_upgrade_row_v1(table, COLUMNS[table], updated)
            classified.append((row, updated, 'preserved_exact' if updated == row else 'payload_erased_retained_facts'))
        output[table] = tuple(classified)
    return output


def registered_source_v1(catalogue_hash):
    for source in SOURCES + APPEND_ONLY_SOURCES:
        if source.catalogue_hash == catalogue_hash:
            return source
    raise ValueError("unregistered source catalogue; no schema conversion is authorized")


def current_catalogue_hash_v1(db):
    rows = db.execute(
        "SELECT c.name,c.owner_kinds,c.storage_role,c.immutable,c.schema_version,"
        "a.writer_domain,a.schema_hash FROM graph_type_catalog c "
        "JOIN graph_type_authority a ON a.name=c.name ORDER BY c.name").fetchall()
    if (not rows or len(rows) != db.execute("SELECT COUNT(*) FROM graph_type_catalog").fetchone()[0]
            or len(rows) != db.execute("SELECT COUNT(*) FROM graph_type_authority").fetchone()[0]):
        raise ValueError("catalogue and writer-authority rows are incomplete")
    material = [[name, json.loads(owners), role, bool(immutable), version, writer or None, digest or None]
                for name, owners, role, immutable, version, writer, digest in rows]
    return _digest(material)


def registered_source_registry_v1(target_registry, source_hash):
    """Reconstruct the complete source through one immutable exact target contract."""
    if type(target_registry) is not TypeRegistry:
        raise TypeError("actual target type registry required")
    source = registered_source_v1(source_hash)
    target = registered_target_v1(source_hash, target_registry.catalogue_hash)
    if len(target_registry.specs) != target.type_count:
        raise ValueError("registered target catalogue type count differs")
    appended = dict(target.appended_types)
    if not set(appended) <= {spec.name for spec in target_registry.specs}:
        raise ValueError("registered target is missing an exact appended type")
    registry = TypeRegistry()
    for spec in target_registry.specs:
        if spec.name in appended:
            if (spec.owner_kinds, spec.storage_role, spec.immutable, spec.schema_version,
                    spec.writer_domain, spec.schema_hash) != appended[spec.name]:
                raise ValueError("registered appended type identity differs")
            continue
        if target.translator == "d05.current-heads.v2" and spec.name in CHANGED_TYPES:
            if (spec.writer_domain != "d05" or spec.schema_version != 2
                    or spec.owner_kinds != ("relation",) or spec.immutable
                    or spec.schema_hash != TARGET_D05_HASHES[spec.name]):
                raise ValueError("registered D05 v2 target writer/shape differs")
            spec = replace(spec, schema_version=1, schema_hash=(
                OLD_CONTRIBUTION_HASH if spec.name == "d05.contribution" else source.projection_schema_hash))
        registry.register(spec)
    if registry.catalogue_hash != source.catalogue_hash:
        raise ValueError("target differs outside the exact registered full-catalogue contract")
    return registry


def install_catalogue_upgrade_schema_v1(db):
    if not db.in_transaction:
        raise ValueError("catalogue migration schema needs its authorized Graph transaction")
    for name, sql in DDL.items():
        old = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        if old is None:
            db.execute(sql)
        elif old != (sql,):
            raise ValueError("catalogue upgrade technical schema differs")


def _operation(db, scope):
    return db.execute(f"SELECT * FROM {OPERATIONS} WHERE bot=? AND persona=? AND operation_id=?",
                      (*scope.namespace.as_tuple, scope.operation_id)).fetchone()


def _metadata(db, namespace):
    row = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                     "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if row is None:
        raise ValueError("catalogue upgrade requires actual existing Graph recovery identity")
    return row


def _assert_current(db, scope, registry, operation):
    if not db.in_transaction or registry.catalogue_hash != scope.target_catalogue_hash:
        raise ValueError("catalogue upgrade is outside its exact target transaction")
    if operation[:8] != (*scope.namespace.as_tuple, scope.operation_id, scope.request_digest,
                         scope.source_catalogue_hash, scope.target_catalogue_hash,
                         registered_source_v1(scope.source_catalogue_hash).package_zip_sha256,
                         scope.target_manifest_digest):
        raise EventConflict("catalogue upgrade retry changes its frozen original")
    if _metadata(db, scope.namespace) != (operation[13], operation[14]):
        raise StaleRead("Graph identity/revision changed outside the catalogue migration")
    expected = scope.target_catalogue_hash if operation[8] == "completed" else scope.source_catalogue_hash
    if current_catalogue_hash_v1(db) != expected:
        raise StaleRead("catalogue upgrade source/target publication changed")


def _begin(db, scope, registry):
    source = registered_source_v1(scope.source_catalogue_hash)
    registered_source_registry_v1(registry, source.catalogue_hash)
    install_catalogue_upgrade_schema_v1(db)
    previous = _operation(db, scope)
    if previous is not None:
        _assert_current(db, scope, registry, previous)
        return previous
    if current_catalogue_hash_v1(db) != source.catalogue_hash:
        raise ValueError("actual source catalogue is not the registered migration input")
    pending = db.execute(f"SELECT operation_id FROM {OPERATIONS} WHERE phase!='completed' LIMIT 1").fetchone()
    if pending is not None:
        raise ValueError("another catalogue migration already owns this Graph")
    namespaces = db.execute("SELECT bot,persona FROM graph_recovery_metadata_v2").fetchall()
    if namespaces != [scope.namespace.as_tuple]:
        raise ValueError("catalogue upgrade requires the actually admitted single-namespace Graph")
    metadata = _metadata(db, scope.namespace)
    for name, identity in registered_target_v1(scope.source_catalogue_hash, registry.catalogue_hash).appended_types:
        if db.execute("SELECT 1 FROM graph_atoms WHERE type_name=? LIMIT 1", (name,)).fetchone():
            raise ValueError("pinned source already contains a newly registered type")
    db.execute(f"INSERT INTO {OPERATIONS} VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
               (*scope.namespace.as_tuple, scope.operation_id, scope.request_digest,
                source.catalogue_hash, registry.catalogue_hash, source.package_zip_sha256,
                scope.target_manifest_digest, "convert", "", 0, 0, 0, *metadata, scope.started_at))
    return _operation(db, scope)


def _check_reads(db, namespace, versions):
    for version in versions:
        if (version.key.owner.bot, version.key.owner.persona) != namespace.as_tuple:
            raise ValueError("catalogue conversion read crosses namespace")
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (version.key.token,)).fetchone()
        if (row[0] if row else 0) != version.revision:
            raise StaleRead("catalogue conversion read changed")


def _append_head(db, *, key, old, value_json, valid, dependencies, event_id, operation):
    """One audited schema revision; old history and consumed keys are untouched."""
    revision = (old[0] if old else 0) + 1
    namespace = (key.owner.bot, key.owner.persona)
    deps_json = canonical_json([[ref, rev] for ref, rev in dependencies])
    if old is None:
        db.execute("INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,name,revision,value,valid) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?)", (key.token, *namespace, key.owner.kind,
                   key.owner.subject, key.type_name, key.name, revision, value_json, int(valid)))
    else:
        changed = db.execute("UPDATE graph_atoms SET revision=?,value=?,valid=? WHERE token=? AND revision=? AND value=? AND valid=?",
                             (revision, value_json, int(valid), key.token, *old)).rowcount
        if changed != 1:
            raise StaleRead("catalogue conversion current-head CAS lost")
    db.execute("INSERT INTO graph_history(token,revision,value,valid,dependencies,event_bot,event_persona,event_session,event_id) "
               "VALUES(?,?,?,?,?,?,?,?,?)", (key.token, revision, value_json, int(valid), deps_json,
               *namespace, MIGRATION_ID, event_id))
    db.execute("DELETE FROM graph_dependencies WHERE dependent_token=?", (key.token,))
    db.executemany("INSERT INTO graph_dependencies(dependent_token,dependency_token,dependency_revision) VALUES(?,?,?)",
                   ((key.token, ref, rev) for ref, rev in dependencies))
    db.execute(f"INSERT OR IGNORE INTO {FRONTIER} VALUES(?,?,?,?,?,0)",
               (*namespace, operation[2], key.token, ""))
    return [key.token, revision]


def _convert(db, store, scope, operation):
    from .d05_production_operations_v1 import collect_d05_catalogue_migration_batch_v2
    from ..domains.d05.relationship import translate_d05_current_heads_v2

    if registered_target_v1(scope.source_catalogue_hash, store._registry.catalogue_hash).translator == "append-only.v1":
        return "verify", "", (), (), (), 0, 0, ()
    material = collect_d05_catalogue_migration_batch_v2(
        db, scope.namespace, operation[9], MAX_BATCH_ROWS)
    if material.source_catalogue_hash != scope.source_catalogue_hash:
        raise ValueError("D05 migration material has another source catalogue")
    if not material.batch_tokens:
        return "invalidate", "", (), (), (), 0, 0, ()
    if (len(material.batch_tokens) > MAX_BATCH_ROWS
            or tuple(sorted(set(material.batch_tokens))) != material.batch_tokens
            or material.batch_tokens[0] <= operation[9]
            or material.next_after not in (None, material.batch_tokens[-1])):
        raise ValueError("D05 migration page is not a bounded monotone cursor")
    batch = translate_d05_current_heads_v2(
        material.snapshot, scope.namespace, material.batch_tokens,
        authenticated_recollections=material.authenticated_recollections,
        legacy_consumed_keys=material.legacy_consumed_keys,
        source_catalogue_hash=scope.source_catalogue_hash)
    _check_reads(db, scope.namespace, batch.read_versions)
    if set(batch.source_tokens) != set(material.batch_tokens) or len(batch.writes) > 64:
        raise ValueError("D05 migration batch changes its actual selected sources")
    validity = dict(batch.current_validity)
    writes = tuple(batch.writes)
    if len({w.key.token for w in writes}) != len(writes) or set(validity) != {w.key.token for w in writes}:
        raise ValueError("D05 migration validity must cover each exact write")
    encoded = [(write, canonical_json(store._registry.validate(write.key, write.value))) for write in writes]
    if sum(len(value.encode()) for _, value in encoded) > MAX_BATCH_BYTES:
        raise ValueError("D05 migration material exceeds the registered encoded batch bound")
    expected = {v.key.token: v.revision for v in batch.read_versions}
    event_id = scope.operation_id + ":" + str(operation[10])
    revisions = []
    for write, value in encoded:
        key = write.key
        if (key.type_name not in CHANGED_TYPES or key.owner.kind != "relation"
                or (key.owner.bot, key.owner.persona) != scope.namespace.as_tuple
                or key.token not in expected or type(validity[key.token]) is not bool):
            raise ValueError("catalogue conversion may only write its typed D05 heads")
        old = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if old is not None and not old[2] and validity[key.token]:
            raise ValueError("schema migration cannot resurrect an invalid current head")
        dependencies = []
        for dependency in write.dependencies:
            if dependency.token not in expected:
                raise ValueError("migration dependency lacks its current read")
            row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (dependency.token,)).fetchone()
            if validity[key.token] and row is not None and not row[1]:
                raise ValueError("migration cannot qualify a current invalid dependency")
            dependencies.append((dependency.token, row[0] if row else 0))
        revisions.append(_append_head(db, key=key, old=old, value_json=value,
            valid=validity[key.token], dependencies=dependencies, event_id=event_id, operation=operation))
    unresolved = sum(write.value.get("identity_status") == "legacy_unresolved" for write in writes)
    return "convert", material.batch_tokens[-1], tuple(revisions), (), tuple(batch.coverage_gaps), len(writes), unresolved, tuple((v.key.token, v.revision) for v in batch.read_versions)


def _invalidate(db, store, scope, operation):
    """Page the reverse closure without collecting a whole Graph in memory."""
    current = db.execute(f"SELECT token,edge_cursor FROM {FRONTIER} WHERE bot=? AND persona=? AND operation_id=? "
                         "AND done=0 ORDER BY token LIMIT 1", (*scope.namespace.as_tuple, scope.operation_id)).fetchone()
    if current is None:
        return "verify", "", (), (), (), 0, 0, ()
    token, cursor = current
    rows = db.execute("SELECT dependent_token FROM graph_dependencies WHERE dependency_token=? "
                      "AND dependent_token>? ORDER BY dependent_token LIMIT ?", (token, cursor, MAX_BATCH_ROWS)).fetchall()
    event_id = scope.operation_id + ":" + str(operation[10])
    invalidated = []
    reads = []
    for (dependent,) in rows:
        key = AtomKey.from_token(dependent)
        if (key.owner.bot, key.owner.persona) != scope.namespace.as_tuple:
            raise ValueError("catalogue migration dependency crosses namespace")
        old = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (dependent,)).fetchone()
        db.execute(f"INSERT OR IGNORE INTO {FRONTIER} VALUES(?,?,?,?,?,0)",
                   (*scope.namespace.as_tuple, scope.operation_id, dependent, ""))
        if old is not None:
            reads.append((dependent, old[0]))
        if old is None:
            raise ValueError("catalogue reverse dependency has no current head")
        dependency = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (token,)).fetchone()
        recorded = db.execute("SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? AND dependency_token=?",
                              (dependent, token)).fetchone()
        if dependency is not None and dependency[1] and recorded == (dependency[0],):
            continue
        if old[2]:
            dependencies = db.execute("SELECT dependency_token,dependency_revision FROM graph_dependencies "
                                      "WHERE dependent_token=? ORDER BY dependency_token", (dependent,)).fetchall()
            invalidated.append(_append_head(db, key=key, old=old, value_json=old[1], valid=False,
                dependencies=dependencies, event_id=event_id, operation=operation))
    if len(rows) < MAX_BATCH_ROWS:
        db.execute(f"UPDATE {FRONTIER} SET done=1 WHERE bot=? AND persona=? AND operation_id=? AND token=?",
                   (*scope.namespace.as_tuple, scope.operation_id, token))
    elif rows:
        db.execute(f"UPDATE {FRONTIER} SET edge_cursor=? WHERE bot=? AND persona=? AND operation_id=? AND token=?",
                   (rows[-1][0], *scope.namespace.as_tuple, scope.operation_id, token))
    return "invalidate", "", (), tuple(invalidated), (), 0, 0, tuple(reads)


def _verify(db, store, scope, operation):
    rows = db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
                      "AND type_name IN ('d05.contribution','d05.relationship_projection') AND token>? "
                      "ORDER BY token LIMIT ?", (*scope.namespace.as_tuple, operation[9], MAX_BATCH_ROWS)).fetchall()
    for token, raw in rows:
        store._registry.validate(AtomKey.from_token(token), json.loads(raw))
    if rows:
        return "verify", rows[-1][0], (), (), (), 0, 0, ()
    registered_source_registry_v1(store._registry, scope.source_catalogue_hash)
    contract = registered_target_v1(scope.source_catalogue_hash, store._registry.catalogue_hash)
    changed = CHANGED_TYPES if contract.translator == "d05.current-heads.v2" else ()
    for name in sorted(changed):
        spec = store._registry.spec(name)
        if db.execute("UPDATE graph_type_catalog SET schema_version=? WHERE name=? AND schema_version=1",
                      (spec.schema_version, name)).rowcount != 1:
            raise StaleRead("catalogue publication lost its source schema version")
        source = registered_source_v1(scope.source_catalogue_hash)
        old_hash = OLD_CONTRIBUTION_HASH if name == "d05.contribution" else source.projection_schema_hash
        if db.execute("UPDATE graph_type_authority SET schema_hash=? WHERE name=? AND writer_domain='d05' AND schema_hash=?",
                      (spec.schema_hash, name, old_hash)).rowcount != 1:
            raise StaleRead("catalogue publication lost its registered source hash")
    for name in sorted(dict(contract.appended_types)):
        spec = store._registry.spec(name)
        db.execute("INSERT INTO graph_type_catalog VALUES(?,?,?,?,?)",
                   (name, canonical_json(list(spec.owner_kinds)), spec.storage_role, int(spec.immutable), spec.schema_version))
        db.execute("INSERT INTO graph_type_authority VALUES(?,?,?)", (name, spec.writer_domain, spec.schema_hash))
    if current_catalogue_hash_v1(db) != scope.target_catalogue_hash:
        raise ValueError("complete target catalogue differs after registered publication")
    return "completed", operation[9], (), (), (), 0, 0, ()


def advance_graph_catalogue_upgrade_in_transaction_v1(store, scope):
    """Called only by GraphStore's issued-maintenance entry, inside one tx."""
    db = store._db
    operation = _begin(db, scope, store._registry)
    _assert_current(db, scope, store._registry, operation)
    if operation[8] == "completed":
        return json.loads(operation[16])
    phase, cursor, revisions, invalidated, gaps, converted, unresolved, reads = {
        "convert": _convert, "invalidate": _invalidate, "verify": _verify,
    }[operation[8]](db, store, scope, operation)
    index = operation[10]
    event_id = scope.operation_id + ":" + str(index)
    epoch_row = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", scope.namespace.as_tuple).fetchone()
    epoch = (epoch_row[0] if epoch_row else 0) + 1
    input_digest = _digest([scope.request_digest, operation[8], operation[9], index, reads, revisions, invalidated, gaps])
    receipt = dict(schema="sylanne.graph-catalogue-upgrade-receipt.v1", migration_id=MIGRATION_ID,
        operation_id=scope.operation_id, namespace=list(scope.namespace.as_tuple),
        source_catalogue_hash=scope.source_catalogue_hash, target_catalogue_hash=scope.target_catalogue_hash,
        target_manifest_digest=scope.target_manifest_digest, batch_index=index,
        phase=phase, cursor=cursor, converted_rows=operation[11] + converted,
        unresolved_rows=operation[12] + unresolved, graph_epoch=epoch,
        graph_revision=operation[14] + 1, coverage_gaps=list(gaps))
    encoded = canonical_json(receipt)
    db.execute("INSERT INTO graph_events(bot,persona,session,event_id,digest,reads,epoch_reads,revisions,invalidated,epoch_revision) "
               "VALUES(?,?,?,?,?,?,?,?,?,?)", (*scope.namespace.as_tuple, MIGRATION_ID, event_id, input_digest,
               canonical_json(list(reads)), "[]", canonical_json(list(revisions)), canonical_json(list(invalidated)), epoch))
    db.execute("INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,?) ON CONFLICT(bot,persona) DO UPDATE SET revision=excluded.revision",
               (*scope.namespace.as_tuple, epoch))
    if db.execute("UPDATE graph_recovery_metadata_v2 SET graph_revision=graph_revision+1 WHERE bot=? AND persona=? "
                  "AND graph_revision=? AND requirements_json=?", (*scope.namespace.as_tuple, operation[14], operation[13])).rowcount != 1:
        raise StaleRead("migration recovery identity CAS changed")
    db.execute(f"INSERT INTO {BATCHES} VALUES(?,?,?,?,?,?,?,?,?)", (*scope.namespace.as_tuple, scope.operation_id,
               index, operation[8], operation[9], cursor, input_digest, encoded))
    db.execute(f"UPDATE {OPERATIONS} SET phase=?,cursor=?,batch_index=batch_index+1,converted_rows=?,unresolved_rows=?,"
               "expected_graph_revision=expected_graph_revision+1,completion_json=? WHERE bot=? AND persona=? AND operation_id=? AND batch_index=?",
               (phase, cursor, receipt["converted_rows"], receipt["unresolved_rows"], encoded if phase == "completed" else None,
                *scope.namespace.as_tuple, scope.operation_id, index))
    return receipt
