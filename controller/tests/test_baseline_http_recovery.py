"""Final-fence and recovery replay with an independent other-controller writer."""

from __future__ import annotations

from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.baseline_admission import BaselineAdmission
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_http_seam_lifetime import assert_free, assert_held
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


@pytest.mark.parametrize("phase", ["final-fence", "recovery"])
def test_acquired_lease_final_and_recovery_replay(
    approval_repo: Any, monkeypatch: Any, phase: str
) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL final/recovery transactions; Memory serialized races covered over HTTP")
    repo.create_baseline_scope(config(), "reviewer", START)
    request = prepare(repo)
    peer = (
        SQLiteRepository(repo._path)
        if isinstance(repo, SQLiteRepository)
        else PostgresRepository(repo.database_url, None)
    )
    assert peer.connection is not None
    permit = BaselineAdmission()
    original = bs._publication_transaction.__exit__
    fired = []
    winner = []
    source = repo.get_job(request.source_job_id)

    def exit(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        value = original(owner, kind, error, tb)
        if owner.connection is repo.connection:
            if not owner.write and not fired:
                fired.append("initial")
                if phase == "final-fence":
                    winner.append(
                        peer.publish_baseline_source(config().scope_id, request, "reviewer", START)
                    )
                else:
                    peer.delete_job(request.source_job_id)
            elif owner.write and phase == "recovery" and not winner:
                assert error is not None
                assert_held(permit)
                peer.save_job(source)
                winner.append(
                    peer.publish_baseline_source(config().scope_id, request, "reviewer", START)
                )
                fired.append("recovery")
        return value

    try:
        with monkeypatch.context() as m:
            m.setattr(bs._publication_transaction, "__exit__", exit)
            result = repo.publish_baseline_source(
                config().scope_id, request, "reviewer", START, admission=permit
            )
        assert not result.created and winner[0].created and result.receipt == winner[0].receipt
        assert fired == (["initial"] if phase == "final-fence" else ["initial", "recovery"])
        assert repo.page_baseline_control_events(config().scope_id).total == 1
        assert_free(permit)
    finally:
        peer.close()
