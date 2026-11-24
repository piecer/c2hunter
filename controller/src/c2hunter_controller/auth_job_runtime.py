"""Per-instance job security binding and post-commit, audit-only repair."""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import partial
from typing import TYPE_CHECKING, cast

from .auth_store import AuthStore

if TYPE_CHECKING:
    from .ai_analysis import AIAnalysisService
    from .ai_investigation import InvestigationService
    from .ai_job_investigation import JobInvestigationService
    from .pcap_export_queue import PcapExportQueue


def wire_job_audit(
    store: AuthStore | None,
    *,
    ai_service: AIAnalysisService | None,
    investigation_service: InvestigationService | None,
    job_investigation_service: JobInvestigationService | None,
    pcap_export_queue: PcapExportQueue,
) -> None:
    """Bind only these instances; never initialize, dispatch or reconcile at startup."""
    if ai_service is not None:
        ai_service.auth_store = store
    if investigation_service is not None:
        investigation_service.store.auth_store = store
    if job_investigation_service is not None:
        job_investigation_service.store.auth_store = store
    pcap_export_queue.auth_store = store


_LOG = logging.getLogger(__name__)


def repair_pending_page(
    store: AuthStore | None,
    family: str,
    read_status: Callable[[str], str | None],
    *,
    cursor: str | None = None,
) -> str | None:
    """One bounded page per maintenance pass; rotate past other families/live work."""
    if store is None:
        return cursor
    try:
        page = store.pending_job_links(limit=100, cursor=cursor)
        for link in page["items"]:
            if link.family == family:
                repair_job_audit(
                    store,
                    family,
                    link.resource_id,
                    partial(read_status, link.resource_id),
                )
        return cast(str | None, page["next_cursor"])
    except Exception:
        _LOG.warning("Pending job audit scan deferred", extra={"job_family": family})
        return cursor


def repair_job_audit(
    store: AuthStore | None,
    family: str,
    resource_id: str,
    read_status: Callable[[], str | None],
) -> str:
    """Never turn committed domain work into failure or repeat its provider call.

    The pending durable link is the recovery record. Do not log raw exceptions,
    which can contain credentials from a failing storage adapter.
    """
    if store is None:
        return "unknown"
    try:
        status = read_status()
        if status is None:
            return "unknown"
        return store.finish_job(family, resource_id, status)
    except Exception:
        _LOG.warning("Job audit repair deferred", extra={"job_family": family})
        return "pending"
