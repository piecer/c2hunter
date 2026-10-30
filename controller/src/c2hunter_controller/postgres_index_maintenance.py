"""Explicit, transactional removal of four proven redundant PostgreSQL indexes.

Not a runtime readiness check. Caller owns the migration connection and commit.
All candidates and keepers are validated before any DROP, under bounded locks.
"""

from __future__ import annotations

from typing import Any

from psycopg.sql import SQL, Identifier

from .postgres_schema import SchemaNotReady

# table, redundant secondary, constraint-backed keeper, constraint type, exact keys
TARGETS = (
    (
        "candidate_records",
        "candidate_records_job_position",
        "candidate_records_job_id_position_key",
        "u",
        ("job_id", "position"),
    ),
    (
        "job_flow_record_chunks",
        "job_flow_record_chunks_job_id",
        "job_flow_record_chunks_pkey",
        "p",
        ("job_id", "chunk_no"),
    ),
    (
        "pcap_offset_index_packets",
        "pcap_offset_index_packets_lookup",
        "pcap_offset_index_packets_pkey",
        "p",
        ("build_id", "packet_index"),
    ),
    (
        "pcap_posting_index_chunks",
        "pcap_posting_index_chunks_read",
        "pcap_posting_index_chunks_pkey",
        "p",
        ("build_id", "dimension", "canonical_value", "chunk_ordinal"),
    ),
)


class RedundantIndexMismatch(SchemaNotReady):
    """Fail closed: operator must investigate an unexpected catalog definition."""


def _relation(cursor: Any, schema: int, name: str) -> tuple[Any, ...] | None:
    cursor.execute(
        "SELECT oid,relkind,relispartition FROM pg_catalog.pg_class "
        "WHERE relnamespace=%s AND relname=%s",
        (schema, name),
    )
    row = cursor.fetchone()
    return tuple(row) if row is not None else None


def _index(
    cursor: Any, oid: int, table: int, columns: tuple[str, ...], *, primary: bool, unique: bool
) -> Any:
    cursor.execute(
        "SELECT i.indrelid,i.indisprimary,i.indisunique,i.indisexclusion,"
        "i.indisvalid,i.indisready,i.indislive,i.indimmediate,i.indisreplident,"
        "i.indisclustered,i.indnkeyatts,i.indnatts,i.indpred IS NULL,"
        "i.indexprs IS NULL,am.amname,i.indnullsnotdistinct,"
        "i.indkey::smallint[],i.indclass::oid[],i.indcollation::oid[],i.indoption::smallint[] "
        "FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid "
        "JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE i.indexrelid=%s",
        (oid,),
    )
    row = cursor.fetchone()
    expected = (
        table,
        primary,
        unique,
        False,
        True,
        True,
        True,
        True,
        False,
        False,
        len(columns),
        len(columns),
        True,
        True,
        "btree",
        False,
    )
    if row is None or tuple(row[:16]) != expected:
        raise RedundantIndexMismatch()
    keys, opclasses, collations, options = row[16:]
    cursor.execute(
        "SELECT a.attnum,a.attname,t.typname,opc.oid,a.attcollation "
        "FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid=a.atttypid "
        "JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace "
        "JOIN pg_catalog.pg_opclass opc ON opc.opcintype=a.atttypid "
        "JOIN pg_catalog.pg_am am ON am.oid=opc.opcmethod "
        "JOIN pg_catalog.pg_namespace n ON n.oid=opc.opcnamespace "
        "WHERE a.attrelid=%s AND a.attname=ANY(%s) AND NOT a.attisdropped "
        "AND a.attnum>0 AND tn.nspname='pg_catalog' AND n.nspname='pg_catalog' "
        "AND opc.opcdefault AND am.amname='btree'",
        (table, list(columns)),
    )
    attrs = {r[1]: r for r in cursor.fetchall()}
    types = {
        "position": "int4",
        "chunk_no": "int4",
        "packet_index": "int8",
        "chunk_ordinal": "int8",
        "canonical_value": "bytea",
    }
    if set(attrs) != set(columns) or any(attrs[c][2] != types.get(c, "text") for c in columns):
        raise RedundantIndexMismatch()
    cursor.execute(
        "SELECT oid FROM pg_catalog.pg_collation WHERE collname='default' AND collnamespace='p"
        "g_catalog'::regnamespace"
    )
    default_collation = cursor.fetchone()[0]
    wanted_collations = [default_collation if attrs[c][2] == "text" else 0 for c in columns]
    if (
        list(keys) != [attrs[c][0] for c in columns]
        or list(opclasses) != [attrs[c][3] for c in columns]
        or list(collations) != wanted_collations
        or [attrs[c][4] for c in columns] != wanted_collations
        or list(options) != [0] * len(columns)
    ):
        raise RedundantIndexMismatch()
    cursor.execute(
        "SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=%s OR inhparent=%s", (oid, oid)
    )
    if cursor.fetchone():
        raise RedundantIndexMismatch()
    return tuple(row)


def _snapshot(cursor: Any, schema: int) -> list[Any]:
    result = []
    for table_name, extra_name, keeper_name, kind, columns in TARGETS:
        table = _relation(cursor, schema, table_name)
        keeper = _relation(cursor, schema, keeper_name)
        extra = _relation(cursor, schema, extra_name)
        if (
            table is None
            or table[1:] != ("r", False)
            or keeper is None
            or keeper[1:] != ("i", False)
        ):
            raise RedundantIndexMismatch()
        table_oid, keeper_oid = table[0], keeper[0]
        keeper_shape = _index(
            cursor, keeper_oid, table_oid, columns, primary=kind == "p", unique=True
        )
        cursor.execute(
            "SELECT oid,conrelid,connamespace,contype,convalidated,condeferrable,condeferred,"
            "conkey,conparentid,conname FROM pg_catalog.pg_constraint WHERE conindid=%s "
            "AND contype IN ('p','u','x')",
            (keeper_oid,),
        )
        constraints = cursor.fetchall()
        if len(constraints) != 1 or tuple(constraints[0][1:]) != (
            table_oid,
            schema,
            kind,
            True,
            False,
            False,
            list(keeper_shape[16]),
            0,
            keeper_name,
        ):
            raise RedundantIndexMismatch()
        extra_shape = None
        if extra is not None:
            if extra[1:] != ("i", False):
                raise RedundantIndexMismatch()
            oid = extra[0]
            extra_shape = _index(cursor, oid, table_oid, columns, primary=False, unique=False)
            cursor.execute("SELECT 1 FROM pg_catalog.pg_constraint WHERE conindid=%s", (oid,))
            if cursor.fetchone():
                raise RedundantIndexMismatch()
            # Ordinary secondary indexes depend only on their indexed table columns.
            # Reject extension/constraint ownership and every unexpected incoming edge.
            cursor.execute(
                "SELECT classid='pg_catalog.pg_class'::regclass,objsubid,"
                "refclassid='pg_catalog.pg_class'::regclass,refobjid,refobjsubid,deptype "
                "FROM pg_catalog.pg_depend WHERE classid='pg_catalog.pg_class'::regclass AND o"
                "bjid=%s",
                (oid,),
            )
            dependencies = cursor.fetchall()
            wanted = {(True, 0, True, table_oid, key, "a") for key in extra_shape[16]}
            if len(dependencies) != len(wanted) or set(dependencies) != wanted:
                raise RedundantIndexMismatch()
            cursor.execute(
                "SELECT 1 FROM pg_catalog.pg_depend WHERE refclassid='pg_catalog.pg_class'::re"
                "gclass AND refobjid=%s",
                (oid,),
            )
            if cursor.fetchone():
                raise RedundantIndexMismatch()
        result.append((table, keeper, constraints, keeper_shape, extra, extra_shape))
    return result


def remove_redundant_indexes(cursor: Any, *, lock_timeout_seconds: float) -> None:
    """Caller must hold the Stage1 session migration advisory lock, outside runtime."""
    # Bound each lock and the entire multi-table LOCK statement. Restore on commit.
    millis = max(1, min(5000, int(lock_timeout_seconds * 1000)))
    cursor.execute("SELECT set_config('lock_timeout',%s,true)", (f"{millis}ms",))
    cursor.execute("SELECT set_config('statement_timeout',%s,true)", (f"{millis * 4}ms",))
    cursor.execute("SELECT oid,nspname FROM pg_catalog.pg_namespace WHERE nspname=current_schema()")
    schema, name = cursor.fetchone()
    before = _snapshot(cursor, schema)
    cursor.execute(
        SQL("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE").format(
            SQL(", ").join(Identifier(name, target[0]) for target in TARGETS)
        )
    )
    cursor.execute("SELECT oid,nspname FROM pg_catalog.pg_namespace WHERE nspname=current_schema()")
    if cursor.fetchone() != (schema, name) or _snapshot(cursor, schema) != before:
        raise RedundantIndexMismatch()
    for target, state in zip(TARGETS, before, strict=True):
        if state[4] is not None:
            if _relation(cursor, schema, target[1]) != state[4]:
                raise RedundantIndexMismatch()
            cursor.execute(SQL("DROP INDEX {} RESTRICT").format(Identifier(name, target[1])))
    # Table locks prevent DROP/rebuild of the original indexes, but PostgreSQL
    # still permits ALTER INDEX RENAME. Names alone cannot prove removal: a
    # concurrent rename may have substituted another index under a target name.
    # Verify the original OIDs disappeared before committing any transactional
    # DROP. If an original survived under another name, roll back the whole phase.
    cursor.execute(
        "SELECT oid FROM pg_catalog.pg_class WHERE oid=ANY(%s)",
        ([state[4][0] for state in before if state[4] is not None],),
    )
    if cursor.fetchone() is not None:
        raise RedundantIndexMismatch()
    after = _snapshot(cursor, schema)
    if any(
        new[:4] != old[:4] or new[4:] != (None, None)
        for old, new in zip(before, after, strict=True)
    ):
        raise RedundantIndexMismatch()
