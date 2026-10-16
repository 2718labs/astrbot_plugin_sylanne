"""Durable Contact scheduling metadata; these rows never grant execution rights."""
import json
from ..runtime_contracts import canonical_serialize

TABLE = 'graph_contact_background_scheduler_v3'
DDL = '''CREATE TABLE graph_contact_background_scheduler_v3(
bot TEXT NOT NULL,persona TEXT NOT NULL,contact_id TEXT NOT NULL,after_key TEXT NOT NULL,
plan_digest TEXT,state TEXT NOT NULL CHECK(state IN ('cursor','waiting','held','unknown','progress','complete')),
phase TEXT,dependencies_json TEXT NOT NULL,result_code TEXT NOT NULL,observed_graph_revision INTEGER NOT NULL,
PRIMARY KEY(bot,persona,contact_id))'''
COLUMNS = ('bot','persona','contact_id','after_key','plan_digest','state','phase','dependencies_json','result_code','observed_graph_revision')


def install_contact_scheduler_schema_v3(db):
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
    if row != (DDL,):
        raise ValueError('Contact durable scheduler exact metadata schema differs')


def validate_contact_scheduler_row_v3(columns,row):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise ValueError('Contact scheduler exact columns differ')
    bot,persona,contact,after,plan,state,phase,encoded,code,revision = row
    dependencies = json.loads(encoded)
    if (state not in {'cursor','waiting','held','unknown','progress','complete'}
            or state == 'cursor' and contact != '' or state != 'cursor' and not contact.startswith('contact:')
            or phase not in {None,'contact_generation','contact_review','final'}
            or type(revision) is not int or revision < 0 or not bot or not persona
            or type(code) is not str or not code or len(code) > 128
            or type(dependencies) is not dict or set(dependencies) != {'graph_revision','graph_epoch','plan_original_digest','condition'}
            or dependencies['graph_revision'] != revision
            or type(dependencies['graph_epoch']) is not int or dependencies['graph_epoch'] < 0
            or dependencies['plan_original_digest'] != plan
            or dependencies['condition'] not in {'sweep','source_authority_policy','original_terminal_cost','final_dispatch','none'}
            or canonical_serialize(dependencies) != encoded
            or plan is not None and (len(plan) != 64 or any(c not in '0123456789abcdef' for c in plan))):
        raise ValueError('Contact scheduler has no exact non-authoritative wake metadata')
    return dependencies


def read_contact_scheduler_cursor_v3(db,namespace):
    row = db.execute(f'SELECT after_key FROM {TABLE} WHERE bot=? AND persona=? AND contact_id=?',
        (*namespace.as_tuple,'')).fetchone()
    return '' if row is None else row[0]


def record_contact_scheduler_progress_v3(graph,bootstrap,bundle,*,contact_id,phase,status,code):
    graph._admin(bootstrap)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise ValueError('Contact scheduler requires its actual installed controller')
    ns = bundle.installation_policy.namespace
    store = graph._GraphCoordinator__store
    with store._lock:
        db = store._db
        db.execute('BEGIN IMMEDIATE')
        try:
            metadata,epoch = graph._v2_graph_stamp(ns)
            original = db.execute('SELECT payload_digest FROM graph_contact_expression_plan_originals_v2 '
                'WHERE bot=? AND persona=? AND contact_id=?',(*ns.as_tuple,contact_id)).fetchone() if contact_id else None
            plan_digest = None if original is None else original[0]
            condition = ('sweep' if not contact_id else 'source_authority_policy' if status == 'held'
                else 'original_terminal_cost' if status in {'waiting','unknown'} else 'final_dispatch' if phase == 'final' else 'none')
            dependencies = {'graph_revision':metadata.graph_revision,'graph_epoch':epoch.revision,
                'plan_original_digest':plan_digest,'condition':condition}
            row = (*ns.as_tuple,contact_id,contact_id,plan_digest,status,phase,canonical_serialize(dependencies),code,metadata.graph_revision)
            validate_contact_scheduler_row_v3(COLUMNS,row)
            db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(bot,persona,contact_id) DO UPDATE SET '
                'after_key=excluded.after_key,plan_digest=excluded.plan_digest,state=excluded.state,phase=excluded.phase,'
                'dependencies_json=excluded.dependencies_json,result_code=excluded.result_code,observed_graph_revision=excluded.observed_graph_revision',row)
            cursor_deps = {'graph_revision':metadata.graph_revision,'graph_epoch':epoch.revision,
                'plan_original_digest':None,'condition':'sweep'}
            db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(bot,persona,contact_id) DO UPDATE SET '
                'after_key=excluded.after_key,dependencies_json=excluded.dependencies_json,observed_graph_revision=excluded.observed_graph_revision',
                (*ns.as_tuple,'',contact_id,None,'cursor',None,canonical_serialize(cursor_deps),'sweep',metadata.graph_revision))
            db.commit()
        except BaseException:
            db.rollback()
            raise
