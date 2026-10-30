"""Real PG redundant-index maintenance contract; opt-in owned fixture only."""

import pytest
from psycopg.sql import SQL, Identifier

from tests import test_postgres_schema_lifecycle as lifecycle

database = lifecycle.database
repository = lifecycle.repository

EXTRAS = {
    "candidate_records_job_position": ("candidate_records", "job_id,position"),
    "job_flow_record_chunks_job_id": ("job_flow_record_chunks", "job_id,chunk_no"),
    "pcap_offset_index_packets_lookup": ("pcap_offset_index_packets", "build_id,packet_index"),
    "pcap_posting_index_chunks_read": (
        "pcap_posting_index_chunks",
        "build_id,dimension,canonical_value,chunk_ordinal",
    ),
}


def extras(control):
    return control.execute(
        "SELECT c.relname,c.oid FROM pg_class c WHERE c.relnamespace=current_schema()::regname"
        "space AND c.relname=ANY(%s) ORDER BY c.relname",
        (list(EXTRAS),),
    ).fetchall()


def seed_extras(control):
    for name, (table, columns) in EXTRAS.items():
        control.execute(
            SQL("CREATE INDEX IF NOT EXISTS {} ON {} ({})").format(
                Identifier(name), Identifier(table), SQL(columns)
            )
        )


def test_existing_indexes_are_removed_idempotently_without_touching_data_or_keys(database):
    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    control.execute(
        "INSERT INTO candidate_records(candidate_id,job_id,position,data) VALUES ('c','j',1,'{}')"
    )
    control.execute("INSERT INTO job_flow_record_chunks VALUES ('j',0,'{}')")
    control.execute(
        "INSERT INTO pcap_capture_source_versions VALUES ('PCAP_UPLOAD','src','object','v',1,r"
        "epeat('a',64),now())"
    )
    control.execute(
        "INSERT INTO pcap_offset_index_generations VALUES ('build','PCAP_UPLOAD','src','v',1,r"
        "epeat('a',64),'PCAP',1,1,'READY',now(),1,1,repeat('b',64))"
    )
    control.execute("INSERT INTO pcap_offset_index_packets VALUES ('build',0,24,40,1,1,17,0,0,0,1)")
    control.execute(
        "INSERT INTO pcap_posting_index_generations VALUES ('posting','PCAP_UPLOAD','src','v',"
        "1,repeat('a',64),'PCAP','build',repeat('b',64),1,1,1,1,1,'READY',now(),1,1,1,1,1,1,AR"
        "RAY['ALL_PACKET'],repeat('c',64),'binding',1,'lease',NULL)"
    )
    control.execute(
        "INSERT INTO pcap_posting_index_chunks VALUES ('posting','ALL_PACKET','',0,0,0,1,'encoded')"
    )
    lookups = [
        "SELECT * FROM pcap_offset_index_packets WHERE build_id='build' AND packet_index>=0 OR"
        "DER BY packet_index",
        "SELECT * FROM pcap_posting_index_chunks WHERE build_id='posting' AND dimension='ALL_P"
        "ACKET' AND canonical_value='' ORDER BY chunk_ordinal",
    ]
    rows = [control.execute(query).fetchall() for query in lookups]
    keys = control.execute(
        "SELECT oid,conindid,pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace=c"
        "urrent_schema()::regnamespace ORDER BY oid"
    ).fetchall()
    repo.upsert_sensor({"sensor_id": "sentinel"})
    audit = control.execute("SELECT * FROM audit_events").fetchall()
    try:
        for _ in range(2):
            repo.initialize_schema()
            assert extras(control) == []
            assert (
                control.execute(
                    "SELECT oid,conindid,pg_get_constraintdef(oid) FROM pg_constraint WHERE co"
                    "nnamespace=current_schema()::regnamespace ORDER BY oid"
                ).fetchall()
                == keys
            )
            assert control.execute(
                "SELECT candidate_id FROM candidate_records WHERE job_id='j' ORDER BY position"
            ).fetchall() == [("c",)]
            assert control.execute(
                "SELECT data FROM job_flow_record_chunks WHERE job_id='j' ORDER BY chunk_no"
            ).fetchall() == [({},)]
            assert control.execute("SELECT * FROM audit_events").fetchall() == audit
            assert [control.execute(query).fetchall() for query in lookups] == rows
        import psycopg

        with pytest.raises(psycopg.errors.UniqueViolation):
            control.execute(
                "INSERT INTO candidate_records(candidate_id,job_id,position,data) VALUES ('oth"
                "er','j',1,'{}')"
            )
        for table in (
            "job_flow_record_chunks",
            "pcap_offset_index_packets",
            "pcap_posting_index_chunks",
        ):
            with pytest.raises(psycopg.errors.UniqueViolation):
                control.execute(
                    SQL("INSERT INTO {} SELECT * FROM {}").format(
                        Identifier(table), Identifier(table)
                    )
                )
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            control.execute(
                "INSERT INTO pcap_offset_index_packets VALUES ('absent',0,24,40,1,1,17,0,0,0,1)"
            )
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            control.execute(
                "INSERT INTO pcap_posting_index_chunks VALUES ('absent','ALL_PACKET','',0,0,0,"
                "1,'encoded')"
            )
    finally:
        repo.close()


def test_fresh_migration_does_not_create_redundant_indexes(database):
    dsn, control = database
    repository(dsn).initialize_schema()
    assert extras(control) == []


@pytest.mark.parametrize("name", list(EXTRAS))
def test_every_target_rejects_same_name_wrong_table_without_partial_drop(database, name):
    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    control.execute(SQL("DROP INDEX {}").format(Identifier(name)))
    control.execute(SQL("CREATE INDEX {} ON controller_objects(id)").format(Identifier(name)))
    before = extras(control)
    from c2hunter_controller.postgres_index_maintenance import RedundantIndexMismatch

    with pytest.raises(RedundantIndexMismatch):
        repo.initialize_schema()
    assert extras(control) == before
    assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []
    assert repo.ready() is False


@pytest.mark.parametrize(
    "definition",
    [
        "ON candidate_records(position,job_id)",
        "ON candidate_records(job_id DESC,position)",
        "ON candidate_records(job_id NULLS FIRST,position)",
        "ON candidate_records(job_id,position) INCLUDE(candidate_id)",
        "ON candidate_records(job_id,position) WHERE position>0",
        "ON candidate_records(lower(job_id),position)",
        "ON candidate_records(job_id text_pattern_ops,position)",
        'ON candidate_records(job_id COLLATE "C",position)',
        "UNIQUE ON candidate_records(job_id,position)",
        "TABLE",
    ],
)
def test_same_name_nonstandard_definition_is_preserved(database, definition):
    from c2hunter_controller.postgres_index_maintenance import RedundantIndexMismatch

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    name = "candidate_records_job_position"
    control.execute(SQL("DROP INDEX {}").format(Identifier(name)))
    if definition == "TABLE":
        control.execute(SQL("CREATE TABLE {}(id int)").format(Identifier(name)))
    elif definition.startswith("UNIQUE"):
        control.execute(
            SQL("CREATE UNIQUE INDEX {} " + definition.removeprefix("UNIQUE ")).format(
                Identifier(name)
            )
        )
    else:
        control.execute(SQL("CREATE INDEX {} " + definition).format(Identifier(name)))
    before = extras(control)
    with pytest.raises(RedundantIndexMismatch):
        repo.initialize_schema()
    assert extras(control) == before
    assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []


@pytest.mark.parametrize(
    "role", ["cluster", "constraint", "extension", "keeper_missing", "keeper_invalid"]
)
def test_roles_and_missing_or_invalid_keeper_refuse_removal(database, role):
    from c2hunter_controller.postgres_index_maintenance import RedundantIndexMismatch

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    if role == "cluster":
        control.execute("ALTER TABLE candidate_records CLUSTER ON candidate_records_job_position")
    elif role == "constraint":
        control.execute("DROP INDEX candidate_records_job_position")
        control.execute(
            "ALTER TABLE candidate_records ADD CONSTRAINT candidate_records_job_position UNIQU"
            "E(job_id,position)"
        )
    elif role == "extension":
        # Synthetic extension dependency: PG16 disallows direct ADD INDEX.
        control.execute(
            "INSERT INTO pg_depend(classid,objid,objsubid,refclassid,refobjid,refobjsubid,dept"
            "ype) SELECT 'pg_class'::regclass,'candidate_records_job_position'::regclass,0,'pg"
            "_extension'::regclass,oid,0,'e' FROM pg_extension WHERE extname='plpgsql'"
        )
    elif role == "keeper_missing":
        control.execute(
            "DROP INDEX candidate_records_job_position"
        )  # Missing extra cannot skip keeper validation.
        control.execute(
            "ALTER TABLE candidate_records DROP CONSTRAINT candidate_records_job_id_position_key"
        )
    else:
        # Synthetic catalog damage on owned DB: real PostgreSQL query exercises validity guard.
        control.execute(
            "UPDATE pg_index SET indisvalid=false WHERE indexrelid='candidate_records_job_id_p"
            "osition_key'::regclass"
        )
    before = extras(control)
    try:
        with pytest.raises(RedundantIndexMismatch):
            repo.initialize_schema()
        assert extras(control) == before
        assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []
    finally:
        if role == "extension":
            control.execute(
                "DELETE FROM pg_depend WHERE classid='pg_class'::regclass AND objid='candidate"
                "_records_job_position'::regclass AND deptype='e'"
            )


def test_partial_absence_and_foreign_schema_same_name_are_idempotent(database):
    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    control.execute("DROP INDEX candidate_records_job_position")
    schema = control.execute("SELECT current_schema()").fetchone()[0] + "_foreign"
    control.execute(SQL("CREATE SCHEMA {}").format(Identifier(schema)))
    try:
        control.execute(SQL("CREATE TABLE {}(id int)").format(Identifier(schema, "other")))
        control.execute(
            SQL("CREATE INDEX candidate_records_job_position ON {}(id)").format(
                Identifier(schema, "other")
            )
        )
        foreign = control.execute(
            "SELECT oid FROM pg_class WHERE relnamespace=%s::regnamespace AND relname='candida"
            "te_records_job_position'",
            (schema,),
        ).fetchone()
        for _ in range(2):
            repo.initialize_schema()
            assert extras(control) == []
            assert (
                control.execute(
                    "SELECT oid FROM pg_class WHERE relnamespace=%s::regnamespace AND relname="
                    "'candidate_records_job_position'",
                    (schema,),
                ).fetchone()
                == foreign
            )
    finally:
        control.execute(SQL("DROP SCHEMA {} CASCADE").format(Identifier(schema)))


def test_bounded_table_lock_timeout_leaves_all_indexes_and_no_ready_marker(database, monkeypatch):
    import time

    import psycopg

    from c2hunter_controller import postgres_index_maintenance as maintenance

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    before = extras(control)
    original = maintenance.remove_redundant_indexes
    with psycopg.connect(dsn) as blocker:

        def blocked(cursor, **kwargs):
            blocker.execute("LOCK TABLE candidate_records IN ACCESS SHARE MODE")
            start = time.monotonic()
            try:
                return original(cursor, **kwargs)
            finally:
                assert time.monotonic() - start < 2
                blocker.rollback()

        monkeypatch.setattr(maintenance, "remove_redundant_indexes", blocked)
        with pytest.raises(psycopg.errors.LockNotAvailable):
            repo.initialize_schema(lock_timeout_seconds=0.05)
    assert extras(control) == before
    assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []


@pytest.mark.parametrize("columns", ["position,job_id", "job_id,position"])
def test_catalog_change_after_preview_is_rechecked_before_any_drop(database, monkeypatch, columns):
    from c2hunter_controller import postgres_index_maintenance as maintenance

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    original = maintenance._snapshot
    calls = []

    def mutate(cursor, schema):
        snapshot = original(cursor, schema)
        calls.append(True)
        if len(calls) == 1:
            control.execute("DROP INDEX candidate_records_job_position")
            control.execute(
                SQL("CREATE INDEX candidate_records_job_position ON candidate_records({})").format(
                    SQL(columns)
                )
            )
        return snapshot

    monkeypatch.setattr(maintenance, "_snapshot", mutate)
    with pytest.raises(maintenance.RedundantIndexMismatch):
        repo.initialize_schema()
    # Same shape with a replacement OID must also abort before DROP.
    assert len(calls) == (1 if columns == "position,job_id" else 2)
    assert len(extras(control)) == 4
    assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []


def test_matching_but_nonallowlisted_keeper_and_secondary_are_rejected(database):
    from c2hunter_controller.postgres_index_maintenance import RedundantIndexMismatch

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    control.execute("DROP INDEX candidate_records_job_position")
    control.execute(
        "ALTER TABLE candidate_records DROP CONSTRAINT candidate_records_job_id_position_key"
    )
    control.execute(
        "ALTER TABLE candidate_records ADD CONSTRAINT "
        "candidate_records_job_id_position_key UNIQUE(position,job_id)"
    )
    control.execute(
        "CREATE INDEX candidate_records_job_position ON candidate_records(position,job_id)"
    )
    before = extras(control)
    with pytest.raises(RedundantIndexMismatch):
        repo.initialize_schema()
    assert extras(control) == before


def test_late_drop_failure_rolls_back_all_removals(database, monkeypatch):
    import psycopg

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    before = extras(control)
    connect = psycopg.connect
    drops = []
    failure = RuntimeError("second DROP refused")

    class FaultCursor(psycopg.Cursor):
        def execute(self, query, *args, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self)
            if text.startswith("DROP INDEX"):
                drops.append(text)
                if len(drops) == 2:
                    raise failure
            return super().execute(query, *args, **kwargs)

    def fault_connection(*args, **kwargs):
        return connect(*args, cursor_factory=FaultCursor, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(psycopg, "connect", fault_connection)
        with pytest.raises(RuntimeError) as raised:
            repo.initialize_schema()
        assert raised.value is failure
    assert len(drops) == 2 and all(text.endswith(" RESTRICT") for text in drops)
    assert extras(control) == before
    assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []
    repo.initialize_schema()
    assert extras(control) == []


@pytest.mark.parametrize("seam", ["recheck", "drop"])
def test_index_rename_after_locked_recheck_cannot_delete_a_same_name_replacement(
    database, monkeypatch, seam
):
    from c2hunter_controller import postgres_index_maintenance as maintenance

    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    seed_extras(control)
    control.execute("CREATE TABLE unrelated(id integer)")
    control.execute("CREATE INDEX unrelated_index ON unrelated(id)")
    original_oid = control.execute(
        "SELECT 'candidate_records_job_position'::regclass::oid"
    ).fetchone()[0]
    foreign_oid = control.execute("SELECT 'unrelated_index'::regclass::oid").fetchone()[0]
    snapshot = maintenance._snapshot
    calls = []
    drops = []

    def rename():
        control.execute("ALTER INDEX candidate_records_job_position RENAME TO parked_original")
        control.execute("ALTER INDEX unrelated_index RENAME TO candidate_records_job_position")

    import psycopg

    connect = psycopg.connect

    class ObservedCursor(psycopg.Cursor):
        def execute(self, query, *args, **kwargs):
            text = query if isinstance(query, str) else query.as_string(self)
            if text.startswith("DROP INDEX"):
                drops.append(text)
                if seam == "drop" and len(drops) == 1:
                    rename()  # Last possible name substitution, after all identity checks.
            return super().execute(query, *args, **kwargs)

    def observed_connection(*args, **kwargs):
        return connect(*args, cursor_factory=ObservedCursor, **kwargs)

    monkeypatch.setattr(psycopg, "connect", observed_connection)

    def rename_after_recheck(cursor, schema):
        result = snapshot(cursor, schema)
        calls.append(True)
        if len(calls) == 2 and seam == "recheck":
            # PostgreSQL permits index RENAME despite ACCESS EXCLUSIVE on its table.
            rename()
        return result

    monkeypatch.setattr(maintenance, "_snapshot", rename_after_recheck)
    with pytest.raises(maintenance.RedundantIndexMismatch):
        repo.initialize_schema()
    assert len(calls) >= 2
    assert (len(drops) == 0) if seam == "recheck" else (len(drops) > 0)
    assert control.execute("SELECT 'parked_original'::regclass::oid").fetchone() == (original_oid,)
    assert control.execute("SELECT 'candidate_records_job_position'::regclass::oid").fetchone() == (
        foreign_oid,
    )
    assert len(extras(control)) == 4
    assert control.execute("SELECT * FROM controller_schema_version").fetchall() == []
