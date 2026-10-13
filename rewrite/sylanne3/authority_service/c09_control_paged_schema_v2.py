"""Exact registered Control metadata objects for paged C09 physical evidence."""
from __future__ import annotations
from .contract import AuthorityUnavailable


def _objects():
    from .c09_physical_inventory_stream_v2 import PHYSICAL_INVENTORY_DDLS_V2, PHYSICAL_INVENTORY_TRIGGERS_V2
    yield from (("table",name,ddl) for name,ddl in PHYSICAL_INVENTORY_DDLS_V2.items())
    yield from (("trigger",name,ddl) for name,ddl in PHYSICAL_INVENTORY_TRIGGERS_V2)


def require_paged_control_schema_v2(db):
    for kind,name,ddl in _objects():
        row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
        if row is None or row[0]!=ddl:
            raise AuthorityUnavailable("C09 registered paged Control schema differs: "+name)


def install_paged_control_schema_v2(control, db, meter):
    """Install only the closed fixed schema in the actual protected transaction."""
    control._registered()
    for kind,name,ddl in _objects():
        row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
        if row is None:
            meter.charge_write(len(ddl.encode("utf-8")))
            db.execute(ddl)
        elif row[0]!=ddl:
            raise AuthorityUnavailable("C09 paged Control object conflicts: "+name)
    require_paged_control_schema_v2(db)


def require_closure_verification_control_schema_v2(db):
    from ..runtime.c09_graph_rebase_candidate_v2 import (
        CLOSURE_VERIFICATION_CONTROL_DDLS_V2,CLOSURE_VERIFICATION_CONTROL_INDEXES_V2,
        CLOSURE_VERIFICATION_CONTROL_TRIGGERS_V2)
    for name,ddl in CLOSURE_VERIFICATION_CONTROL_DDLS_V2.items():
        row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
        if row is None or row[0]!=ddl:
            raise AuthorityUnavailable("C09 protected closure verification work schema differs: "+name)
    for kind,values in (("index",CLOSURE_VERIFICATION_CONTROL_INDEXES_V2),("trigger",CLOSURE_VERIFICATION_CONTROL_TRIGGERS_V2)):
        for ddl in values:
            name=ddl.split()[2]
            row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
            if row is None or row[0]!=ddl:
                raise AuthorityUnavailable("C09 protected closure verification work object differs: "+name)
