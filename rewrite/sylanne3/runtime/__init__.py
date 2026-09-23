"""Alpha1 runtime infrastructure that is installed into the business SQLite authority."""

from .budget import BudgetLease, BudgetReceipt, install_schema as _install_budget_schema
from .clock import (
    CharacterClockMapping, PersistentDeadline, RebuiltDeadline,
    install_schema as _install_clock_schema,
)
from .jobs import PersistentJob, install_schema as _install_job_schema


def install_schema(db) -> None:
    """Install every P0-D table into the coordinator-owned connection.

    This function performs DDL only.  It intentionally leaves commit and
    rollback control with the caller, just like every mutation in this package.
    """
    _install_budget_schema(db)
    _install_job_schema(db)
    _install_clock_schema(db)

__all__ = [
    "BudgetLease", "BudgetReceipt", "CharacterClockMapping",
    "PersistentDeadline", "PersistentJob", "RebuiltDeadline", "install_schema",
]
