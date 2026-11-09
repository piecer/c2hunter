"""Opt-in JOB byte custody, not a JOB schema or semantic validation service.

The owner must initialize explicitly. No production reader/admission migrates JOB.
A later typed producer validates source, execution, pool and model semantics before
passing canonical bytes here. This facade does not turn arbitrary JSON into valid
model evidence. Distributed mixed-old-version capacity is unsupported.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .ai_investigation_store import (
    _JOB_PROFILE,
    InvestigationRunStore,
    _initialize_profile,
)


def initialize_job_investigation_store(repository: Any) -> None:
    """Explicit owner-only JOB schema/index initialization."""
    _initialize_profile(repository, _JOB_PROFILE)


class JobInvestigationRunStore(InvestigationRunStore):
    def __init__(self, repository: Any, *, clock: Callable[[], float] = time.time) -> None:
        super().__init__(repository, clock=clock, _profile=_JOB_PROFILE)
