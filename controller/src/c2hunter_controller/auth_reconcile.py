"""Bounded audit-only readers for configured persistent controller metadata.

No worker, model, queue dispatcher, schema initializer, or blob client is started.
MemoryRepository has no cross-process authority and is explicitly unsupported.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from .ai_investigation_store import InvestigationRunStore
from .ai_job_investigation_store import JobInvestigationRunStore
from .auth_models import AuthError, JobLink


class RepositoryJobReader:
    """Use the real adapters and their independent schema/readiness guards."""

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    def __call__(self, link: JobLink) -> str | None:
        try:
            if link.family == "analysis":
                row = self.repository.get_job_summary(link.resource_id)
            elif link.family == "ai_run":
                row = self.repository.get_ai_run(link.resource_id)
            elif link.family == "pcap_export":
                row = self.repository.get_pcap_export_job(link.resource_id)
            elif link.family == "ip_investigation":
                return InvestigationRunStore(self.repository).audit_status(link.resource_id)
            elif link.family == "job_investigation":
                return JobInvestigationRunStore(self.repository).audit_status(link.resource_id)
            else:
                raise AuthError("AUDIT_RECONCILE_UNSUPPORTED", 503)
            return str(row["status"]) if row is not None else None
        except AuthError:
            raise
        except Exception:
            # Never echo SQL, DSNs, private source bodies, or provider exceptions.
            raise AuthError("AUDIT_RECONCILE_UNAVAILABLE", 503) from None


@contextmanager
def configured_reader() -> Iterator[RepositoryJobReader]:
    """The deployable persistent domain backend is PostgreSQL, not auth SQLite."""
    dsn = os.environ.get("C2HUNTER_DATABASE_URL", "memory://")
    if not dsn.startswith(("postgresql://", "postgres://")):
        raise AuthError("AUDIT_RECONCILE_UNSUPPORTED", 503)
    from .production import MinioBlobStore, PostgresRepository

    # These metadata APIs never consume blob_store. Deliberately install no blob
    # capability instead of constructing a client with invented credentials or
    # accessing configured S3. The repository itself is the production SQL adapter.
    repository = PostgresRepository(dsn, cast(MinioBlobStore, None))
    try:
        yield RepositoryJobReader(repository)
    finally:
        repository.close()
