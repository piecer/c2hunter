"""New output DTO closure and storage corruption admissions."""

from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from tests.test_baseline_scope_envelopes import execute
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("mutation", ["clock-admissible", "false-clean", "groups-over-flows"])
def test_source_preview_rejects_contradictory_projection(scope_repo: Any, mutation: str) -> None:
    scope_repo.create_baseline_scope(config(), "admin", START)
    scope_repo.save_job(stored())
    value = scope_repo.preview_baseline_source(
        config().scope_id, "root", 0, "APPROVAL"
    ).to_mapping()
    if mutation == "clock-admissible":
        value["reasons"].append("SOURCE_CLOCK_UNCERTAIN")
        value["reasons"].sort()
    if mutation == "false-clean":
        value["admissible"] = False
    if mutation == "groups-over-flows":
        value["flow_count"] = 0
    with pytest.raises(ValueError):
        g.SourcePreview.from_mapping(value)


@pytest.mark.parametrize(
    "fault", ["digest", "claimed-size", "config-id", "overcount", "overbyte", "dangling"]
)
def test_scope_corruption_never_becomes_missing(
    scope_repo: Any, fault: str, monkeypatch: Any
) -> None:
    repo = scope_repo
    if hasattr(repo, "jobs"):
        pytest.skip("SQL persisted envelope faults")
    repo.create_baseline_scope(config(), "admin", START)
    pg = hasattr(repo, "database_url")
    if fault == "digest":
        execute(repo, "UPDATE baseline_scopes SET config_content_sha256=?", ("f" * 64,))
    elif fault == "claimed-size":
        execute(repo, "UPDATE baseline_scopes SET config_byte_size=config_byte_size+1")
    elif fault == "config-id":
        execute(
            repo, "UPDATE baseline_scopes SET scope_id=?", ("ffffffff-ffff-ffff-ffff-ffffffffffff",)
        )
    elif fault == "dangling":
        execute(
            repo,
            "UPDATE baseline_scopes SET state='HAS_REFERENCE',active_generation_id=?",
            ("ffffffff-ffff-ffff-ffff-ffffffffffff",),
        )
    elif fault == "overcount":
        for i in range(16):
            execute(
                repo,
                "INSERT INTO baseline_scopes SELECT "
                "?,config_json,config_byte_size,config_content_sha256,config_sha256,created_by,created_at,control_revision,frozen,state,accepted_event_end,active_generation_id,previous_generation_id"
                " FROM baseline_scopes LIMIT 1",
                (f"00000000-0000-0000-0000-{i:012d}",),
            )
    else:
        if pg:
            from psycopg import sql

            names = execute(
                repo,
                "SELECT conname FROM pg_constraint WHERE "
                "conrelid='baseline_scopes'::regclass AND contype='c'",
            ).fetchall()
            for (name,) in names:
                repo.connection.execute(
                    sql.SQL("ALTER TABLE baseline_scopes DROP CONSTRAINT {}").format(
                        sql.Identifier(name)
                    )
                )
        else:
            execute(repo, "PRAGMA ignore_check_constraints=ON")
        execute(repo, "UPDATE baseline_scopes SET config_json=?", ("é" * 65536,))
    repo.connection.commit()
    if fault in ("overbyte", "overcount"):
        monkeypatch.setattr(
            bs.r, "_decode", lambda *_a, **_k: pytest.fail("unadmitted config crossed decoder")
        )
        original = bs._SQL.execute

        def no_payload(self: Any, statement: str, values: tuple = ()) -> Any:
            assert not statement.startswith("SELECT config_json,"), (
                "unadmitted config crossed SQL driver"
            )
            return original(self, statement, values)

        monkeypatch.setattr(bs._SQL, "execute", no_payload)
    identifier = (
        "ffffffff-ffff-ffff-ffff-ffffffffffff" if fault == "config-id" else config().scope_id
    )
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.get_baseline_scope(identifier)
