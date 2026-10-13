"""Storage conversion checks; these do not claim installed Owner admission."""
from dataclasses import asdict, replace
import json
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from tempfile import mkdtemp
import os
from types import SimpleNamespace
import unittest
from uuid import uuid4

from sylanne3.contracts import StaleRead, canonical_json
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.domains.d05.relationship import RelationshipContribution
from sylanne3.memory_types import source_key
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_serialize
from sylanne3.runtime.graph_catalogue_upgrade_v1 import (
    APPENDED_TYPES, SOURCES, APPEND_ONLY_SOURCES, TARGET_158_V1, TARGET_163_V1, TARGET_164_V1, advance_graph_catalogue_upgrade_in_transaction_v1,
    current_catalogue_hash_v1, registered_source_registry_v1,
    catalogue_upgrade_c09_rows_v1, OPERATIONS, BATCHES, FRONTIER,
)


@contextmanager
def retained_catalogue_fixture_directory_v1():
    """Keep actual migration/rollback databases for the acceptance receipt."""
    directory = mkdtemp(prefix='catalogue-case-', dir=os.environ.get('SYLANNE_CATALOGUE_FIXTURE_ROOT'))
    yield directory


# Historical target fixture view. These five exact registrations did not exist
# in the frozen 158 catalogue; no historical schema row is rewritten here.
HISTORICAL_158_EXCLUDED_TYPES = frozenset({
    "d01.method_blind_review_request.v2", "d01.method_trial_proposal.v2",
    "d11.contact_p2_qualification.v1", "d13.derived_block_metadata.v1",
    "d13.derived_block_metadata.v2",
    "runtime.contact_platform_observation.v1",
})


class CatalogueUpgradeTests(unittest.TestCase):
    """Historical exact158 storage contract; current163 acceptance is separate."""
    @classmethod
    def setUpClass(cls):
        asset = Path(__file__).resolve().parents[4] / 'resources/catalogue/d04-affect-scheme.json'
        raw = json.loads(asset.read_bytes())
        scheme = AffectScheme(raw['schema'], raw['scheme_version'], raw['operator_version'],
            raw['parameter_version'], raw['coupling_version'], tuple(AffectAxis(**row) for row in raw['axes']),
            tuple(tuple(row) for row in raw['parameter_bounds']))
        current = discover_domain_registry(active_affect_scheme=scheme).type_registry
        cls.registry = TypeRegistry()
        for spec in current.specs:
            if spec.name not in HISTORICAL_158_EXCLUDED_TYPES:
                cls.registry.register(spec)
        if cls.registry.catalogue_hash != TARGET_158_V1.catalogue_hash:
            raise ValueError('historical migration regression must retain the exact frozen 158-type target')

    def _advance(self, store, scope):
        store._db.execute('BEGIN IMMEDIATE')
        try:
            result = advance_graph_catalogue_upgrade_in_transaction_v1(store, scope)
            store._db.execute('COMMIT')
            return result
        except BaseException:
            store._db.execute('ROLLBACK')
            raise

    def test_both_registered_sources_resume_preserve_history_and_invalidate_dependants(self):
        for source in SOURCES:
            with self.subTest(source=source.catalogue_hash), retained_catalogue_fixture_directory_v1() as directory:
                path = Path(directory) / 'graph.sqlite'
                old_registry = registered_source_registry_v1(self.registry, source.catalogue_hash)
                store = GraphStore(path, old_registry)
                namespace = NamespaceId('bot', 'persona')
                scope = SimpleNamespace(namespace=namespace, operation_id=str(uuid4()), request_digest='d'*64,
                    source_catalogue_hash=source.catalogue_hash, target_catalogue_hash=self.registry.catalogue_hash,
                    target_manifest_digest='e'*64, started_at=1.0)
                key = AtomKey(Owner('relation', 'bot', 'persona', 'entity:other'), 'd05.relationship_projection', 'trust')
                dependent = AtomKey(Owner('persona', 'bot', 'persona'), 'd10.project', 'retained-dependent')
                old_contribution = RelationshipContribution('persona:persona', 'family:legacy', 'entity:other',
                    'trust', 'recollection', 1, (source_key('bot', 'persona', 'legacy').token,))
                contribution_key = AtomKey(key.owner, 'd05.contribution', old_contribution.key)
                contribution = dict(owner_persona_ref=old_contribution.owner_persona_ref,
                    canonical_event_or_family_ref=old_contribution.canonical_event_or_family_ref,
                    subject_entity_ref=old_contribution.subject_entity_ref, target_dimension='trust', semantics='recollection',
                    contribution_revision=1, source_refs=list(old_contribution.source_refs))
                raw = canonical_json(dict(subject_entity_ref='entity:other', dimension='trust', status='source_qualified'))
                db = store._db
                requirements = canonical_serialize(asdict(SnapshotRequirementsV2(namespace, 'authority:fixture', 'ns:fixture',
                    1, 'deletion:fixture', 0, 'genesis', 'execution:fixture', 0, 'genesis', 0, 'graph:fixture')))
                db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)",
                    ('bot', 'persona', 'sylanne3.authority.v2', requirements, 7))
                for atom, value in ((key, raw), (dependent, '{"retained":"bytes"}'), (contribution_key, canonical_json(contribution))):
                    db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (atom.token, 'bot', 'persona', atom.owner.kind, atom.owner.subject, atom.type_name, atom.name, 1, value, 1))
                    deps = canonical_json([[key.token, 1]]) if atom == dependent else '[]'
                    db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',
                        (atom.token, 1, value, 1, deps, 'bot', 'persona', 'old-signed', 'old-event'))
                db.execute('INSERT INTO graph_dependencies VALUES(?,?,?)', (dependent.token, key.token, 1))
                before = db.execute('SELECT * FROM graph_history ORDER BY token').fetchall()
                store.close()
                with self.assertRaises(ValueError):
                    GraphStore(path, self.registry)
                store = GraphStore(path, old_registry)
                store._registry = self.registry
                first = self._advance(store, scope)
                self.assertEqual(first['phase'], 'convert')
                with self.assertRaisesRegex(ValueError, 'pending catalogue'):
                    catalogue_upgrade_c09_rows_v1(store._db, affected={key.token})
                store.close()
                # Reopen the unchanged source catalogue after a committed batch.
                store = GraphStore(path, old_registry)
                store._registry = self.registry
                for _ in range(20):
                    receipt = self._advance(store, scope)
                    if receipt['phase'] == 'completed':
                        break
                self.assertEqual(receipt['phase'], 'completed')
                self.assertEqual(self._advance(store, scope), receipt)
                self.assertEqual(current_catalogue_hash_v1(store._db), self.registry.catalogue_hash)
                self.assertEqual(store._db.execute('SELECT * FROM graph_history WHERE revision=1 ORDER BY token').fetchall(), before)
                self.assertEqual(store._db.execute('SELECT valid FROM graph_atoms WHERE token=?', (dependent.token,)).fetchone(), (0,))
                current = json.loads(store._db.execute('SELECT value FROM graph_atoms WHERE token=?', (key.token,)).fetchone()[0])
                self.assertEqual(current['schema_version'], 2)
                self.assertEqual(current['estimate'], 'unknown')
                migrated = json.loads(store._db.execute('SELECT value FROM graph_atoms WHERE token=?', (contribution_key.token,)).fetchone()[0])
                self.assertEqual(migrated['identity_status'], 'legacy_unresolved')
                self.assertIsNone(migrated['recollection_activity_ref'])
                self.assertEqual(store._db.execute('SELECT requirements_json FROM graph_recovery_metadata_v2').fetchone()[0], requirements)
                retained = catalogue_upgrade_c09_rows_v1(store._db, affected={key.token})
                self.assertEqual(set(retained), {OPERATIONS, BATCHES, FRONTIER})
                self.assertTrue(all(row[2] == 'payload_erased_retained_facts' for rows in retained.values() for row in rows))
                self.assertEqual(retained[OPERATIONS][0][1][2:9], retained[OPERATIONS][0][0][2:9])
                self.assertTrue(all(key.token not in canonical_serialize(new) for rows in retained.values() for _,new,_ in rows))
                self.assertTrue(all(row[2] == 'preserved_exact' for rows in catalogue_upgrade_c09_rows_v1(
                    store._db, affected=set()).values() for row in rows))
                store.close()
                GraphStore(path, self.registry).close()

    def test_frozen_145_source_adds_types_without_rewriting_existing_heads_or_history(self):
        source = APPEND_ONLY_SOURCES[0]
        old_registry = registered_source_registry_v1(self.registry, source.catalogue_hash)
        with retained_catalogue_fixture_directory_v1() as directory:
            path = Path(directory) / 'graph.sqlite'
            store = GraphStore(path, old_registry)
            ns = NamespaceId('bot', 'persona')
            db = store._db
            requirements = canonical_serialize(asdict(SnapshotRequirementsV2(ns, 'authority:fixture', 'ns:fixture',
                1, 'deletion:fixture', 0, 'genesis', 'execution:fixture', 0, 'genesis', 0, 'graph:fixture')))
            db.execute('INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)',
                (*ns.as_tuple, 'sylanne3.authority.v2', requirements, 7))
            key = AtomKey(Owner('relation', *ns.as_tuple, 'entity:other'), 'd05.relationship_projection', 'trust')
            value = canonical_json(dict(subject_entity_ref='entity:other', dimension='trust', status='unavailable',
                schema_version=2, source_qualification='unavailable', estimate='unknown', influence_status='not_evaluated'))
            # Retained legitimate v2 metadata remains byte-for-byte unchanged;
            # append-only registration creates no new relationship experience.
            db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
                (key.token, *ns.as_tuple, key.owner.kind, key.owner.subject, key.type_name, key.name, 1, value, 1))
            db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',
                (key.token, 1, value, 1, '[]', *ns.as_tuple, 'original145', 'original-event'))
            original = {table: db.execute('SELECT * FROM '+table).fetchall()
                for table in ('graph_atoms', 'graph_history', 'graph_dependencies')}
            scope = SimpleNamespace(namespace=ns, operation_id=str(uuid4()), request_digest='d'*64,
                source_catalogue_hash=source.catalogue_hash, target_catalogue_hash=self.registry.catalogue_hash,
                target_manifest_digest='e'*64, started_at=1.0)
            store._registry = self.registry
            first = self._advance(store, scope)
            self.assertEqual((first['phase'], first['converted_rows']), ('verify', 0))
            store.close()
            store = GraphStore(path, old_registry); store._registry = self.registry
            for _ in range(4):
                receipt = self._advance(store, scope)
                if receipt['phase'] == 'completed': break
            self.assertEqual((receipt['phase'], receipt['converted_rows'], receipt['unresolved_rows']), ('completed', 0, 0))
            for table, rows in original.items():
                self.assertEqual(store._db.execute('SELECT * FROM '+table).fetchall(), rows)
            self.assertEqual(current_catalogue_hash_v1(store._db), self.registry.catalogue_hash)
            self.assertEqual(self._advance(store, scope), receipt)
            store.close(); GraphStore(path, self.registry).close()

    def test_mid_batch_sqlite_failure_rolls_back_and_reopened_cursor_does_not_duplicate(self):
        with retained_catalogue_fixture_directory_v1() as directory:
            path = Path(directory) / 'graph.sqlite'
            old = SOURCES[0]
            old_registry = registered_source_registry_v1(self.registry, old.catalogue_hash)
            store = GraphStore(path, old_registry)
            namespace = NamespaceId('bot', 'persona')
            scope = SimpleNamespace(namespace=namespace, operation_id=str(uuid4()), request_digest='d'*64,
                source_catalogue_hash=old.catalogue_hash, target_catalogue_hash=self.registry.catalogue_hash,
                target_manifest_digest='e'*64, started_at=1.0)
            db = store._db
            requirements = canonical_serialize(asdict(SnapshotRequirementsV2(namespace, 'authority:fixture', 'ns:fixture',
                1, 'deletion:fixture', 0, 'genesis', 'execution:fixture', 0, 'genesis', 0, 'graph:fixture')))
            db.execute('INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)',
                ('bot', 'persona', 'sylanne3.authority.v2', requirements, 7))
            keys = tuple(AtomKey(Owner('relation', *namespace.as_tuple, 'entity:other'),
                'd05.relationship_projection', dimension) for dimension in ('familiarity', 'trust'))
            for key in keys:
                value = canonical_json(dict(subject_entity_ref='entity:other', dimension=key.name, status='source_qualified'))
                db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (key.token, *namespace.as_tuple, key.owner.kind, key.owner.subject, key.type_name, key.name, 1, value, 1))
                db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',
                    (key.token, 1, value, 1, '[]', *namespace.as_tuple, 'old-signed', 'old-event'))
            observed_tables = ('graph_atoms', 'graph_history', 'graph_events', 'graph_epochs',
                'graph_dependencies', 'graph_recovery_metadata_v2')
            before = {table: db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall() for table in observed_tables}
            # SQLite aborts the second real history append after the first head,
            # history and frontier changes have already run inside this batch.
            # TEMP keeps the interruption local to this connection, so reopen
            # retries the unchanged persisted operation without a test hook.
            db.execute("CREATE TEMP TRIGGER interrupt_second_migration_history BEFORE INSERT ON graph_history "
                "WHEN NEW.event_session='d05.catalogue-upgrade.v2' AND "
                "(SELECT count(*) FROM graph_history WHERE event_session='d05.catalogue-upgrade.v2')=1 "
                "BEGIN SELECT RAISE(ABORT,'interrupted second migration history append'); END")
            store._registry = self.registry
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'interrupted second migration history append'):
                self._advance(store, scope)
            self.assertFalse(db.in_transaction)
            for table, rows in before.items():
                self.assertEqual(db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall(), rows)
            self.assertEqual(db.execute('SELECT name FROM sqlite_master WHERE name IN (?,?,?)',
                (OPERATIONS, BATCHES, FRONTIER)).fetchall(), [])
            self.assertEqual(current_catalogue_hash_v1(db), old.catalogue_hash)
            store.close()

            store = GraphStore(path, old_registry)
            store._registry = self.registry
            first = self._advance(store, scope)
            self.assertEqual((first['phase'], first['batch_index'], first['converted_rows']), ('convert', 0, 2))
            self.assertEqual(first['cursor'], max(key.token for key in keys))
            self.assertEqual(store._db.execute(f'SELECT cursor,batch_index FROM {OPERATIONS}').fetchone(),
                (first['cursor'], 1))
            store.close()

            store = GraphStore(path, old_registry)
            store._registry = self.registry
            for _ in range(12):
                receipt = self._advance(store, scope)
                if receipt['phase'] == 'completed':
                    break
            self.assertEqual(receipt['phase'], 'completed')
            self.assertEqual(receipt['converted_rows'], 2)
            self.assertEqual(store._db.execute('SELECT token,revision FROM graph_atoms ORDER BY token').fetchall(),
                sorted((key.token, 2) for key in keys))
            self.assertEqual(store._db.execute("SELECT token,count(*) FROM graph_history WHERE "
                "event_session='d05.catalogue-upgrade.v2' GROUP BY token ORDER BY token").fetchall(),
                sorted((key.token, 1) for key in keys))
            self.assertEqual(store._db.execute(f'SELECT count(*) FROM {BATCHES}').fetchone(),
                store._db.execute("SELECT count(*) FROM graph_events WHERE session='d05.catalogue-upgrade.v2'").fetchone())
            completed_tables = (*observed_tables, OPERATIONS, BATCHES, FRONTIER)
            completed = {table: store._db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()
                for table in completed_tables}
            self.assertEqual(self._advance(store, scope), receipt)
            for table, rows in completed.items():
                self.assertEqual(store._db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall(), rows)
            store.close()
            GraphStore(path, self.registry).close()

    def test_revision_change_cannot_resume_and_forged_scope_cannot_open(self):
        with retained_catalogue_fixture_directory_v1() as directory:
            source = SOURCES[0]
            store = GraphStore(Path(directory)/'graph.sqlite', registered_source_registry_v1(self.registry, source.catalogue_hash))
            store._db.execute('INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)',
                ('bot', 'persona', 'sylanne3.authority.v2', '{}', 0))
            store._registry = self.registry
            scope = SimpleNamespace(namespace=NamespaceId('bot', 'persona'), operation_id=str(uuid4()), request_digest='d'*64,
                source_catalogue_hash=source.catalogue_hash, target_catalogue_hash=self.registry.catalogue_hash,
                target_manifest_digest='e'*64, started_at=1.0)
            self._advance(store, scope)
            store._db.execute('UPDATE graph_recovery_metadata_v2 SET graph_revision=graph_revision+1')
            with self.assertRaises(StaleRead):
                self._advance(store, scope)
            store.close()
            from sylanne3.authority_service.contract import AuthorityUnavailable
            with self.assertRaises(AuthorityUnavailable):
                GraphStore.open_registered_catalogue_upgrade_v1(scope, self.registry)

    def test_unregistered_append_identity_is_rejected(self):
        registry = TypeRegistry()
        for spec in self.registry.specs:
            if spec.name == next(iter(APPENDED_TYPES)):
                spec = replace(spec, schema_hash='0'*64)
            registry.register(spec)
        with self.assertRaises(ValueError):
            registered_source_registry_v1(registry, SOURCES[0].catalogue_hash)

    def test_c09_core_frozen_request_pending_exclusion_and_consumed_replay(self):
        from sylanne3.authority_service.contract import AuthorityUnavailable
        from sylanne3.authority_service.d12_package_files_v2 import _digest, SELECTION_SCHEMA
        from sylanne3.authority_service.graph_catalogue_upgrade_v1 import (
            TABLE, DDL, COLUMNS, validate_catalogue_upgrade_core_schema_v1,
            validate_catalogue_upgrade_core_row_v1, require_catalogue_operation_unconsumed_in_tx_v1,
        )
        from sylanne3.authority_service.d12_c09_core_rows_v1 import validate_d12_core_row_v1
        operation = str(uuid4())
        pointer = dict(schema=SELECTION_SCHEMA, installation_id='installation:fixture', revision=0, package_epoch=0,
            operation_id=str(uuid4()), release_ref='source', manifest_sha256='a'*64, cohort_ref='cohort:source',
            cohort_digest='b'*64, prior_selection_digest=None)
        pointer['selection_digest'] = _digest(pointer)
        storage = dict(pointer_version=0,manifest_digest='c'*64,storage_generation=0,members=[
            dict(role=role,resolved_path='/var/lib/sylanne/'+role+'.sqlite',device=1,file_id=index+1,
                incarnation_or_journal_id=role+':fixture') for index,role in enumerate(('core','deletion','execution','graph'))])
        request = dict(namespace={'bot_id':'bot','persona_id':'persona'},authority_namespace='ns:fixture',
            installation_id='installation:fixture',operation_id=operation,pause_operation_id=str(uuid4()),
            target_cohort_ref='cohort:target',target_cohort_digest='d'*64,source_catalogue_hash=SOURCES[0].catalogue_hash,
            target_catalogue_hash=self.registry.catalogue_hash,target_manifest_digest='e'*64,actor='owner:fixture',
            storage=storage,selected_pointer=pointer)
        receipt = dict(schema='sylanne.graph-catalogue-upgrade-receipt.v1',migration_id='d05.catalogue-upgrade.v2',
            operation_id=operation,namespace=['bot','persona'],source_catalogue_hash=SOURCES[0].catalogue_hash,
            target_catalogue_hash=self.registry.catalogue_hash,target_manifest_digest='e'*64,batch_index=2,
            phase='completed',cursor='',converted_rows=0,unresolved_rows=0,graph_epoch=3,graph_revision=3,coverage_gaps=[])
        row = ('ns:fixture',operation,_digest(request),request['pause_operation_id'],'cohort:target',
            SOURCES[0].catalogue_hash,self.registry.catalogue_hash,'e'*64,canonical_json(storage),'sha256:'+'f'*64,
            1.0,'completed',canonical_json(receipt),canonical_json(request))
        self.assertEqual(validate_catalogue_upgrade_core_row_v1(COLUMNS,row),(request,receipt))
        self.assertEqual(validate_d12_core_row_v1(TABLE,COLUMNS,row),('ns:fixture','catalogue_upgrade_operation',operation,operation))
        pending = list(row); pending[11],pending[12] = 'pending',None
        with self.assertRaises(AuthorityUnavailable):
            validate_d12_core_row_v1(TABLE,COLUMNS,tuple(pending))
        changed = list(row); changed[13] = canonical_json({**request,'target_cohort_digest':'0'*64})
        with self.assertRaises(AuthorityUnavailable):
            validate_catalogue_upgrade_core_row_v1(COLUMNS,tuple(changed))
        with sqlite3.connect(':memory:',isolation_level=None) as db:
            db.execute(DDL)
            validate_catalogue_upgrade_core_schema_v1(db)
            db.execute('CREATE TABLE authority_c09_consumed_execution_v1(namespace TEXT,kind TEXT,item_id TEXT,'
                'operation_id TEXT,original_commitment TEXT,facts_pin_digest TEXT,PRIMARY KEY(namespace,kind,item_id))')
            db.execute('INSERT INTO authority_c09_consumed_execution_v1 VALUES(?,?,?,?,?,?)',
                ('ns:fixture','catalogue_upgrade_operation',operation,operation,'1'*64,'2'*64))
            db.execute('BEGIN')
            with self.assertRaisesRegex(AuthorityUnavailable,'retired by C09'):
                require_catalogue_operation_unconsumed_in_tx_v1(db,'ns:fixture',operation)
            require_catalogue_operation_unconsumed_in_tx_v1(db,'ns:fixture',str(uuid4()))
            db.rollback()


class CatalogueUpgradeTarget163Tests(unittest.TestCase):
    """Actual current163 source storage, not installed Owner/product qualification."""

    @classmethod
    def setUpClass(cls):
        asset = Path(__file__).resolve().parents[4] / 'resources/catalogue/d04-affect-scheme.json'
        raw = json.loads(asset.read_bytes())
        scheme = AffectScheme(raw['schema'], raw['scheme_version'], raw['operator_version'],
            raw['parameter_version'], raw['coupling_version'], tuple(AffectAxis(**row) for row in raw['axes']),
            tuple(tuple(row) for row in raw['parameter_bounds']))
        current = discover_domain_registry(active_affect_scheme=scheme).type_registry
        cls.registry = TypeRegistry()
        for spec in current.specs:
            if spec.name != 'd13.derived_block_metadata.v2':
                cls.registry.register(spec)
        if cls.registry.catalogue_hash != TARGET_163_V1.catalogue_hash or len(cls.registry.specs) != 163:
            raise ValueError('current migration regression requires the actual exact 163-type target')

    _advance = CatalogueUpgradeTests._advance

    def test_exact163_two_136_sources_and_frozen145_preserve_original_histories(self):
        # Reuse genuine SQLite setup/receipts, not a second migration model.
        CatalogueUpgradeTests.test_both_registered_sources_resume_preserve_history_and_invalidate_dependants(self)
        CatalogueUpgradeTests.test_frozen_145_source_adds_types_without_rewriting_existing_heads_or_history(self)

    def test_exact163_mid_batch_abort_rolls_back_reopens_and_consumes_cursor_once(self):
        CatalogueUpgradeTests.test_mid_batch_sqlite_failure_rolls_back_and_reopened_cursor_does_not_duplicate(self)


class CatalogueUpgradeTarget164Tests(CatalogueUpgradeTarget163Tests):
    """Current V2 catalogue; the historical 158/163 fixtures remain exact."""
    @classmethod
    def setUpClass(cls):
        asset = Path(__file__).resolve().parents[4] / 'resources/catalogue/d04-affect-scheme.json'
        raw = json.loads(asset.read_bytes())
        scheme = AffectScheme(raw['schema'], raw['scheme_version'], raw['operator_version'],
            raw['parameter_version'], raw['coupling_version'], tuple(AffectAxis(**row) for row in raw['axes']),
            tuple(tuple(row) for row in raw['parameter_bounds']))
        cls.registry = discover_domain_registry(active_affect_scheme=scheme).type_registry
        if cls.registry.catalogue_hash != TARGET_164_V1.catalogue_hash or len(cls.registry.specs) != 164:
            raise ValueError('current migration regression requires the actual exact 164-type target')

    test_exact163_two_136_sources_and_frozen145_preserve_original_histories = None
    test_exact163_mid_batch_abort_rolls_back_reopens_and_consumes_cursor_once = None

    def test_exact164_two_136_sources_and_frozen145_preserve_original_histories(self):
        CatalogueUpgradeTests.test_both_registered_sources_resume_preserve_history_and_invalidate_dependants(self)
        CatalogueUpgradeTests.test_frozen_145_source_adds_types_without_rewriting_existing_heads_or_history(self)

    def test_exact164_mid_batch_abort_rolls_back_reopens_and_consumes_cursor_once(self):
        CatalogueUpgradeTests.test_mid_batch_sqlite_failure_rolls_back_and_reopened_cursor_does_not_duplicate(self)


if __name__ == '__main__':
    unittest.main()
