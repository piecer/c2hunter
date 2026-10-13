"""Counts and scalar envelope gates precede driver payload transfer."""

from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from tests import test_baseline_scope_storage as storage_fixtures
from tests import test_historical_read_postgres as pg_fixtures
from tests.test_baseline_scope_envelopes import execute
from tests.test_historical_source import START, config

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("fault", ["generation-count", "actor-bytes", "pointer-bytes"])
def test_envelope_admitted_before_driver_payload(
    scope_repo: Any, fault: str, monkeypatch: Any
) -> None:
    repo = scope_repo
    if hasattr(repo, "jobs"):
        pytest.skip("SQL driver transfer boundary")
    repo.create_baseline_scope(config(), "admin", START)
    if fault == "generation-count":
        for i in range(3):
            execute(
                repo,
                "INSERT INTO baseline_generations VALUES(?,?,?,?,?,?)",
                (config().scope_id, f"00000000-0000-0000-0000-{i:012d}", i + 1, "{}", "0" * 64, 2),
            )
    elif fault == "actor-bytes":
        execute(repo, "UPDATE baseline_scopes SET created_by=?", ("é" * 65536,))
    else:
        execute(repo, "UPDATE baseline_scopes SET active_generation_id=?", ("x" * 65536,))
    repo.connection.commit()
    original = bs._SQL.execute

    def admitted(self: Any, statement: str, values: tuple = ()) -> Any:
        assert not statement.startswith("SELECT config_json,"), (
            "payload transferred before count/scalar gate"
        )
        return original(self, statement, values)

    monkeypatch.setattr(bs._SQL, "execute", admitted)
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.get_baseline_scope(config().scope_id)
