"""Security-lint contracts: runtime guards and code-owned SQL, no PG server."""

import pytest

from c2hunter_controller import historical_ai_descendants as d
from c2hunter_controller import historical_ai_sql as sql
from c2hunter_controller import repositories
from c2hunter_controller.historical_ai_storage import HistoricalStorageError
from c2hunter_controller.repositories import MemoryRepository
from tests.test_historical_ai_access import repo as _repository_fixture
from tests.test_historical_ai_access_metadata import inject
from tests.test_historical_ai_descendants import staged

repo = _repository_fixture


@pytest.mark.parametrize("boundary", ["previous", "observed"])
def test_memory_missing_descendant_readback_is_typed(monkeypatch, boundary):
    repo = MemoryRepository()
    _, proposed = staged(repo, monkeypatch)
    if boundary == "previous":
        repo.save_ai_assessment(proposed)
    original = d.MemoryAccess.get
    fired = []

    def missing(self, kind, identifier):
        if self.repo is repo and kind == "A" and identifier == proposed["id"]:
            fired.append((kind, identifier))
            return None
        return original(self, kind, identifier)

    monkeypatch.setattr(d.MemoryAccess, "get", missing)
    try:
        with pytest.raises(HistoricalStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.save_ai_assessment(proposed)
    finally:
        assert fired == [("A", proposed["id"])]
    monkeypatch.setattr(d.MemoryAccess, "get", original)
    # Neither invariant failure may rewrite the saved identity or owner.
    assert repo.get_ai_assessment(proposed["id"])["id"] == proposed["id"]


def test_sql_admission_missing_reference_is_typed_and_releases_owner(tmp_path):
    from c2hunter_controller import historical_ai_sql as sql
    from c2hunter_controller.baseline_admission import BaselineAdmission, BaselineLease
    from c2hunter_controller.repositories import SQLiteRepository
    from tests.test_historical_ai_storage import prepared

    repo = SQLiteRepository(tmp_path / "guard.db")
    request, _, _ = prepared(repo)
    # Private helper invariant fault: public facades revalidate this DTO first.
    invalid = request.model_copy(
        update={"payload": request.payload.model_copy(update={"baseline_reference": None})}
    )
    admission = BaselineAdmission()
    queried = []
    repo.connection.set_trace_callback(queried.append)
    try:
        with pytest.raises(HistoricalStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            with BaselineLease(admission) as lease:
                with sql.transaction(repo.connection, postgres=False, write=True) as cursor:
                    sql.RunSQL(cursor, False).admit(
                        invalid, lambda *_: pytest.fail("builder reached with no reference"), lease
                    )
        assert any("FROM ai_analysis_runs" in query for query in queried)
        assert any(query == "ROLLBACK" for query in queried)
        assert not repo.connection.in_transaction
        assert repo.connection.execute("SELECT count(*) FROM ai_analysis_runs").fetchone() == (0,)
        with BaselineLease(admission) as lease:
            assert lease.acquire()
    finally:
        repo.connection.close()


def test_missing_bundle_metadata_stays_typed(monkeypatch):
    from c2hunter_controller import historical_ai_storage as custody

    repo = MemoryRepository()
    run, proposed = staged(repo, monkeypatch)
    materialize = custody.materialize_historical_run
    fired = []

    def missing(value):
        view, bundles = materialize(value)
        fired.append(value["id"])
        return view, [bundle.model_copy(update={"metadata": None}) for bundle in bundles]

    monkeypatch.setattr(custody, "materialize_historical_run", missing)
    with pytest.raises(HistoricalStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        d.checked_assessment(proposed, run)
    assert fired == [run["id"]]


def test_public_admission_missing_reference_refuses_before_io(repo, monkeypatch):
    from pydantic import ValidationError

    from tests.test_historical_ai_storage import prepared

    request, _, _ = prepared(repo)
    invalid = request.model_copy(
        update={"payload": request.payload.model_copy(update={"baseline_reference": None})}
    )
    with monkeypatch.context() as patch:
        patch.setattr(
            repo, "get_ai_run_by_request", lambda *_: pytest.fail("storage lookup reached")
        )
        with pytest.raises(ValidationError, match="BASELINE_SOURCE_INVALID") as caught:
            repo.admit_historical_ai_run(invalid, lambda *_: pytest.fail("builder reached"))
    assert caught.value.errors()[0]["loc"] == ("payload",)
    assert caught.value.errors()[0]["ctx"]["error"].code == "BASELINE_SOURCE_INVALID"
    assert repo.get_ai_run(request.run_id) is None
    assert (
        repo.get_ai_run_by_request(request.analysis_job_id, request.payload.idempotency_key) is None
    )


def test_sql_missing_descendant_readback_rolls_back(tmp_path, monkeypatch):
    repo = repositories.SQLiteRepository(tmp_path / "missing.db")
    try:
        _, proposed = staged(repo, monkeypatch)
        fired = []
        repo.connection.create_function("observe_missing", 0, lambda: fired.append(True) or 0)
        repo.connection.execute(
            "CREATE TEMP TRIGGER remove_assessment AFTER INSERT ON ai_candidate_assessments "
            "BEGIN SELECT observe_missing(); "
            "DELETE FROM ai_candidate_assessments WHERE assessment_id=NEW.assessment_id; END"
        )
        with pytest.raises(HistoricalStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.save_ai_assessment(proposed)
        assert fired == [True]
        assert not repo.connection.in_transaction
        assert repo.get_ai_assessment(proposed["id"]) is None
        repo.connection.execute("DROP TRIGGER remove_assessment")
        assert repo.save_ai_assessment(proposed)["id"] == proposed["id"]
    finally:
        repo.connection.close()


def test_historical_guard_requires_all_nodes_and_memory_absence():
    from c2hunter_controller.historical_ai_access import public_ai_access

    node = d.Meta("R", {}, mode=2, historical=True)
    with public_ai_access(2), pytest.raises(HistoricalStorageError):
        d.guard([None, node])
    assert d.MemoryAccess(MemoryRepository()).chain("A", "missing") == [None]


HOSTILE = "x' OR 1=1; DROP TABLE ai_analysis_runs; --?\"雪"


@pytest.mark.parametrize("kind", ["R", "A", "T", "F"])
def test_hostile_legacy_values_are_data_not_sql(repo, kind):
    from c2hunter_controller.historical_ai_access import public_ai_access

    _, _, parent, _ = d.TABLES[kind]
    value = {
        "id": HOSTILE,
        "analysis_job_id": "job-" + HOSTILE,
        "idempotency_key": "key-" + HOSTILE,
        "created_at": "2026-01-01",
        "artifact_type": "SPLUNK_QUERY",
        "private_probe": {HOSTILE: HOSTILE},
        "candidate_snapshots": [{"historical_reference": None, HOSTILE: HOSTILE}],
        "selection_inventory": [{"historical_reference": None, HOSTILE: HOSTILE}],
        "evidence_bundle": {"historical_reference": None, HOSTILE: HOSTILE},
    }
    parent = parent or "analysis_job_id"
    value[parent] = "parent-" + HOSTILE
    if kind == "R":
        assert repo.create_ai_run(value) == (value, True)
    else:
        inject(repo, kind, value)
    getter = getattr(
        repo,
        {
            "R": "get_ai_run",
            "A": "get_ai_assessment",
            "T": "get_ai_artifact",
            "F": "list_ai_feedback",
        }[kind],
    )
    lister = getattr(
        repo,
        {
            "R": "list_ai_runs",
            "A": "list_ai_assessments",
            "T": "list_ai_artifacts",
            "F": "list_ai_feedback",
        }[kind],
    )
    with public_ai_access(None):
        assert getter(value[parent] if kind == "F" else HOSTILE) == (
            [value] if kind == "F" else value
        )
        assert lister(value[parent]) == [value]
        assert lister("no-match-" + HOSTILE) == []
        if kind != "F":
            assert getter("no-match-" + HOSTILE) is None
    if kind == "R":
        assert repo.get_ai_run_by_request(value[parent], value["idempotency_key"]) == value
        assert repo.save_ai_run({**value, "status": "RUNNING"})["status"] == "RUNNING"
    else:
        saver = getattr(
            repo,
            {"A": "save_ai_assessment", "T": "save_ai_artifact", "F": "save_ai_feedback"}[kind],
        )
        assert saver(value) == value
    assert lister(value[parent])


class ScriptedCursor:
    """PG driver responses only; statements are recorded, not executed by a server."""

    def __init__(self, rows):
        self.rows = iter(rows)
        self.calls = []
        self.fetches = 0

    def execute(self, statement, parameters=()):
        self.calls.append((statement, parameters))
        return self

    def fetchone(self):
        self.fetches += 1
        return next(self.rows)

    def fetchall(self):
        self.fetches += 1
        return next(self.rows)


def metadata_row(kind, value):
    node = d.native_meta(kind, value, identity=value["id"])
    assert node is not None
    return (
        True,
        *(node.fields[key] for key in d.IDENTITIES),
        node.mode,
        node.historical,
        node.invalid,
        node.identity_ok,
        node.owner,
        200,
        None,
    )


@pytest.mark.parametrize("kind", ["R", "A", "T", "F"])
@pytest.mark.parametrize("locator", [False, True])
def test_pg_descendant_hostile_identity_is_bound(kind, locator):
    value = {
        "id": HOSTILE,
        "created_at": "2026-01-01",
        "ai_run_id": HOSTILE,
        "assessment_id": HOSTILE,
    }
    count = {"R": 1, "A": 2, "T": 4, "F": 3}[kind]
    cursor = ScriptedCursor([metadata_row(kind, value), *([None] * (count - 1)), (value,)])
    assert d.SQLAccess(cursor, True).get(kind, HOSTILE, locator=locator) == value
    assert cursor.fetches == count + 1
    assert len(cursor.calls) == count + 1
    for statement, parameters in cursor.calls:
        assert HOSTILE not in statement
        assert parameters == (HOSTILE,)
        assert "%s" in statement
    assert ("ctid=%s::tid" if locator else d.TABLES[kind][1] + "=%s") in cursor.calls[-1][0]


@pytest.mark.parametrize("kind", ["A", "T", "F"])
def test_pg_descendant_hostile_list_parent_is_bound(kind):
    cursor = ScriptedCursor([None, []])
    assert d.SQLAccess(cursor, True).list(kind, HOSTILE) == []
    assert cursor.fetches == 2
    for statement, parameters in cursor.calls:
        assert HOSTILE not in statement and parameters == (HOSTILE,)
    assert cursor.calls[-1][0].startswith("SELECT ctid::text FROM ")


@pytest.mark.parametrize("kind", [HOSTILE, "ai_analysis_runs", "R;--"])
def test_unknown_table_selector_never_reaches_driver(kind):
    cursor = ScriptedCursor([])
    with pytest.raises(KeyError):
        d.SQLAccess(cursor, True).get(kind, HOSTILE)
    assert cursor.calls == [] and cursor.fetches == 0


def catalog_rows(name):
    columns = [
        (column, typ, -1, False, "", "", False)
        for column, typ in zip(
            sql.COLUMNS, ("text", "text", "int4", "text", "int4", "text"), strict=True
        )
    ]
    checks = [
        (
            "ai_runs_hist_owner_shape",
            "c",
            True,
            False,
            False,
            False,
            f"({sql._shape(postgres=True)}) IS TRUE",
        )
    ]
    triggers = [("ai_runs_hist_owner_update", 19, "O", False, 0, "", True, 17)]
    functions = [
        (
            17,
            "ai_runs_hist_owner_guard",
            0,
            True,
            "plpgsql",
            False,
            "v",
            "u",
            ["search_path=pg_catalog"],
            sql._pg_guard_body(),
        )
    ]
    return [(11, 12, name), columns, checks, triggers, functions, None]


@pytest.mark.parametrize("name", ['schema"; DROP TABLE ai_analysis_runs; --', 'odd.雪"schema'])
def test_pg_catalog_schema_is_one_quoted_identifier(name):
    from psycopg.sql import Identifier

    cursor = ScriptedCursor(catalog_rows(name))
    sql.postgres_schema(cursor)
    assert cursor.fetches == 6
    assert cursor.calls[-1] == (
        f"SELECT 1 FROM {Identifier(name).as_string()}.ai_analysis_runs WHERE "
        f"({sql._shape(postgres=True)}) IS NOT TRUE LIMIT 1",
        (),
    )
    assert [values for _, values in cursor.calls[1:5]] == [
        (11, list(sql.COLUMNS)),
        (11,),
        (11,),
        (12,),
    ]


def test_pg_legacy_run_update_binds_body_and_identity():
    import json

    value = {
        "id": HOSTILE,
        "analysis_job_id": HOSTILE,
        "idempotency_key": HOSTILE,
        "created_at": "2026-01-01",
        "status": "QUEUED",
    }
    row = (HOSTILE, HOSTILE, HOSTILE, value["created_at"], value, *([None] * 6))
    cursor = ScriptedCursor(
        catalog_rows("public") + [metadata_row("R", value), metadata_row("R", value), row]
    )
    updated = {**value, "status": "RUNNING", "note": HOSTILE}
    assert sql.RunSQL(cursor, True).save(updated) == updated
    assert cursor.fetches == 9
    writes = [
        (statement, values) for statement, values in cursor.calls if statement.startswith("UPDATE ")
    ]
    assert len(writes) == 1
    assert writes[0] == (
        "UPDATE ai_analysis_runs SET data=%s::jsonb WHERE run_id=%s",
        (json.dumps(updated, separators=(",", ":"), default=str), HOSTILE),
    )
    for statement, _ in cursor.calls:
        assert HOSTILE not in statement


@pytest.mark.parametrize("kind", ["A", "T", "F"])
def test_pg_descendant_lock_templates_preserve_order_and_bound_values(monkeypatch, kind):
    from tests.test_historical_ai_descendants import drafts

    memory = MemoryRepository()
    run, assessment, artifacts, feedback = drafts(memory, monkeypatch)
    values = {
        "A": assessment,
        "T": memory.save_ai_artifact(artifacts[0]),
        "F": memory.save_ai_feedback(feedback),
    }
    proposed = values[kind]
    access = d.MemoryAccess(memory)
    cursor = ScriptedCursor(
        [(run["analysis_job_id"],), (run["id"],), (assessment["id"],)]
        + ([] if kind == "A" else [(proposed["id"],)])
    )
    store = d.SQLAccess(cursor, True)
    observed = []

    def chain(level, identifier):
        observed.append((level, identifier))
        return access.chain(level, identifier)

    # Metadata/body driver model uses real Memory custody, not a guard bypass.
    monkeypatch.setattr(store, "chain", chain)
    monkeypatch.setattr(store, "get", access.get)
    monkeypatch.setattr(store, "run", access.run)
    assert store.save(kind, proposed) == proposed
    assert observed.count((kind, proposed["id"])) == 2
    locks = [
        (statement, parameters)
        for statement, parameters in cursor.calls
        if statement.endswith("FOR UPDATE")
    ]
    expected = [
        (
            "SELECT id FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
            (run["analysis_job_id"],),
        ),
        ("SELECT run_id FROM ai_analysis_runs WHERE run_id=%s FOR UPDATE", (run["id"],)),
        (
            "SELECT assessment_id FROM ai_candidate_assessments WHERE assessment_id=%s FOR UPDATE",
            (assessment["id"],),
        ),
    ]
    if kind != "A":
        expected.append(
            (
                "SELECT artifact_id FROM ai_generated_artifacts WHERE artifact_id=%s FOR UPDATE"
                if kind == "T"
                else "SELECT feedback_id FROM ai_feedback WHERE feedback_id=%s FOR UPDATE",
                (proposed["id"],),
            )
        )
    assert locks == expected
    assert cursor.fetches == len(expected)
    assert any(statement.startswith("INSERT INTO ") for statement, _ in cursor.calls)
