"""Fixed-fanout AI metadata gates and caller-owned descendant operations."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from . import historical_ai_storage as custody
from .historical_ai_access import authorize

TABLES = {
    "R": ("ai_analysis_runs", "run_id", "", "ai_runs"),
    "A": ("ai_candidate_assessments", "assessment_id", "ai_run_id", "ai_assessments"),
    "T": ("ai_generated_artifacts", "artifact_id", "assessment_id", "ai_artifacts"),
    "F": ("ai_feedback", "feedback_id", "assessment_id", "ai_feedback"),
}
CAPS = {"R": 65536, "A": 268435456, "T": 33554432, "F": 65536}
IDENTITIES = (
    "id",
    "analysis_job_id",
    "ai_run_id",
    "assessment_id",
    "candidate_id",
    "idempotency_key",
    "created_at",
)
RELEVANT = (
    frozenset(IDENTITIES)
    | custody.PRIVATE_FIELDS
    | {"baseline_mode", "evidence_bundle", "candidate_snapshots", "selection_inventory"}
)


def _leaf(value: Any) -> str | None:
    # No encoding, object protocol calls, or unknown-body traversal during classification.
    return value if type(value) is str and 0 < len(value) <= 200 else None


@dataclass
class Meta:
    kind: str
    fields: dict[str, str | None]
    mode: int = 0  # absent=0, off=1, historical=2, malformed=-1
    historical: bool = False
    invalid: bool = False
    identity_ok: bool = True
    owner: bool = False
    size: int = 0
    created_at: str | None = None


def native_meta(
    kind: str, raw: Any, *, identity: str | None = None, owner: Any = None
) -> Meta | None:
    if raw is None:
        custody.require(owner is None)
        return None
    custody.require(type(raw) is dict)
    mode = (
        0
        if "baseline_mode" not in raw
        else {"off": 1, "historical": 2}.get(raw["baseline_mode"], -1)
        if type(raw["baseline_mode"]) is str
        else -1
    )
    private = bool(custody.PRIVATE_FIELDS.intersection(raw))
    bad = mode == -1
    for key in ("baseline_summary", "baseline_request"):
        if key in raw:
            value = raw[key]
            bad |= type(value) is not dict
            if type(value) is dict:
                if key == "baseline_summary":
                    bad |= value.get("mode") != "historical" or value.get("scope_kind") not in (
                        "OPERATIONAL",
                        "EVALUATION",
                    )
                else:
                    bad |= value.get("baseline_mode") != "historical"
    if "evidence_bundle" in raw:
        bundle = raw["evidence_bundle"]
        bad |= type(bundle) is not dict
        if type(bundle) is dict and bundle.get("historical_reference") is not None:
            private = True
            bad |= type(bundle["historical_reference"]) is not dict
    if kind == "R":
        for name in ("candidate_snapshots", "selection_inventory"):
            rows = raw.get(name)
            if type(rows) in (list, tuple):
                for row in rows:
                    if type(row) is dict and row.get("historical_reference") is not None:
                        private = True
                        bad |= type(row["historical_reference"]) is not dict
    owned = owner is not None
    if owned:
        bad |= type(owner) is not dict or owner.keys() != set(custody.OWNER_FIELDS)
        if type(owner) is dict:
            bad |= owner.get("version") != "historical-ai-owner-v1"
            for prefix, limit in (("request", 16384), ("snapshot", 4194304)):
                text, size = owner.get(prefix + "_canonical_json"), owner.get(prefix + "_byte_size")
                bad |= not (
                    type(text) is str
                    and 1 <= len(text) <= limit
                    and type(size) is int
                    and 1 <= size <= limit
                )
            digest = owner.get("expected_snapshot_sha256")
            bad |= not (
                type(digest) is str
                and len(digest) == 64
                and all(c in "0123456789abcdef" for c in digest)
            )
        bad |= mode != 2
    fields = {k: _leaf(raw.get(k)) for k in IDENTITIES}
    return Meta(
        kind,
        fields,
        mode,
        private or owned or mode == 2,
        bad,
        identity is None or raw.get("id") == identity,
        owned,
    )


def guard(nodes: list[Meta | None], *, compact: bool = False) -> bool:
    present = [node for node in nodes if node is not None]
    custody.require(not any(n.invalid for n in present))
    historical = any(n.historical for n in present)
    if historical:
        custody.require(not any(n.mode == 1 for n in present))
    if historical:
        custody.require(all(n.identity_ok for n in present))
        bykind = {n.kind: n for n in present}
        run = bykind.get("R")
        assessment = bykind.get("A")
        artifact = bykind.get("T")
        if assessment and run:
            custody.require(
                assessment.fields["ai_run_id"] == run.fields["id"]
                and assessment.fields["analysis_job_id"] == run.fields["analysis_job_id"]
            )
        if artifact and assessment and run:
            custody.require(
                artifact.fields["assessment_id"] == assessment.fields["id"]
                and artifact.fields["ai_run_id"] == run.fields["id"]
                and artifact.fields["analysis_job_id"] == run.fields["analysis_job_id"]
            )
    authorize(historical, compact=compact)
    if not historical:
        return False
    custody.require(all(n is not None for n in nodes))
    for node in present:
        custody.require(node.identity_ok)
        needed = {"id", "created_at"}
        if node.kind in ("R", "A", "T"):
            needed.add("analysis_job_id")
        if node.kind in ("A", "T"):
            needed.add("ai_run_id")
        if node.kind in ("T", "F"):
            needed.add("assessment_id")
        if node.kind == "R":
            needed.add("idempotency_key")
            custody.require(node.owner and node.mode == 2)
        if node.kind == "A":
            needed.add("candidate_id")
        try:
            from datetime import datetime
            from uuid import UUID

            for key in needed:
                custody._identifier(node.fields.get(key))
            for key in needed & {"id", "assessment_id", "ai_run_id"}:
                identifier = cast(str, node.fields[key])
                custody.require(str(UUID(identifier)) == identifier)
            stamp = datetime.fromisoformat(cast(str, node.fields["created_at"]))
            custody.require(stamp.tzinfo is not None)
            if node.created_at is not None:
                custody.require(stamp == datetime.fromisoformat(node.created_at))
        except (ValueError, TypeError, OverflowError):
            raise custody.HistoricalStorageError() from None
    return True


def admit_body(value: Any, limit: int) -> None:
    """Bound compact ensure_ascii JSON bytes before copying/encoding any scalar."""
    import math

    remaining = limit

    def charge(size: int) -> None:
        nonlocal remaining
        custody.require(0 <= size <= remaining)
        remaining -= size

    def string(text: str) -> None:
        custody.require(len(text) <= remaining)
        charge(2)
        for char in text:
            code = ord(char)
            charge(
                2
                if char in '"\\\\\b\f\n\r\t'
                else 6
                if code < 32 or 127 <= code <= 65535
                else 12
                if code > 65535
                else 1
            )

    def visit(item: Any, depth: int) -> None:
        custody.require(depth <= 64)
        typ = type(item)
        if typ is str:
            string(item)
        elif item is None or typ is bool:
            charge(4 if item is None or item is True else 5)
        elif typ is int:
            custody.require(item.bit_length() <= 256)
            charge(len(str(item)))
        elif typ is float:
            custody.require(math.isfinite(item))
            charge(len(str(item)))
        elif typ is dict:
            custody.require(len(item) <= remaining // 4)
            charge(2 + max(0, len(item) - 1))
            for key, child in item.items():
                custody.require(type(key) is str)
                string(key)
                charge(1)
                visit(child, depth + 1)
        elif typ in (list, tuple):
            custody.require(len(item) <= remaining)
            charge(2 + max(0, len(item) - 1))
            for child in item:
                visit(child, depth + 1)
        else:
            raise custody.HistoricalStorageError()

    visit(value, 0)


def _mark(raw: dict[str, Any], view: dict[str, Any]) -> dict[str, Any]:
    custody.require(not (custody.PRIVATE_FIELDS - {"baseline_summary"}).intersection(raw))
    custody.require(raw.get("baseline_mode", "historical") == "historical")
    custody.require(
        "baseline_summary" not in raw or raw["baseline_summary"] == view["baseline_summary"]
    )
    return {**raw, "baseline_mode": "historical", "baseline_summary": view["baseline_summary"]}


def checked_assessment(raw: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    from .ai_analysis import CandidateAssessment, validate_assessment_evidence

    try:
        view, bundles = custody.materialize_historical_run(run)
        custody.require(
            raw["ai_run_id"] == run["id"] and raw["analysis_job_id"] == run["analysis_job_id"]
        )
        selected = [
            bundle for bundle in bundles if bundle.candidate.candidate_id == raw["candidate_id"]
        ]
        custody.require(len(selected) == 1)
        bundle = selected[0]
        if bundle.metadata is None:
            raise custody.HistoricalStorageError()
        custody.require(raw["evidence_bundle"] == bundle.model_dump(mode="json", by_alias=True))
        custody.require(raw["evidence_bundle_hash"] == bundle.metadata.canonical_sha256)
        for key in (
            "external_ip",
            "existing_c2hunter_score",
            "prefilter_score",
            "prefilter_score_version",
        ):
            custody.require(raw[key] == getattr(bundle.candidate, key))
        candidate = next(c for c in view["candidate_snapshots"] if c["id"] == raw["candidate_id"])
        for key in ("discovery_origin", "behavior_anomaly_score"):
            custody.require(raw.get(key) == candidate.get(key))
        assessment = CandidateAssessment.model_validate(raw["assessment"])
        validate_assessment_evidence(assessment, bundle)
        return _mark(raw, view)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, StopIteration):
        raise custody.HistoricalStorageError() from None


def checked_child(
    kind: str, raw: dict[str, Any], assessment: dict[str, Any], run: dict[str, Any]
) -> dict[str, Any]:
    import math

    from .ai_analysis import CandidateAssessment
    from .ai_artifacts import SplunkDataProfile, _misp_content, _splunk_content

    try:
        checked = checked_assessment(assessment, run)
        custody.require(raw["assessment_id"] == checked["id"])
        if kind == "F":
            custody._identifier(raw["created_by"])
            custody.require(type(raw["note"]) is str and len(raw["note"]) <= 5000)
            custody.require(
                raw["verdict"]
                in ("CONFIRM_C2", "CONFIRM_BENIGN", "NEED_MORE_DATA", "REJECT_EXPLANATION")
            )
            confidence = raw.get("corrected_confidence")
            custody.require(
                confidence is None
                or (
                    type(confidence) in (int, float)
                    and math.isfinite(confidence)
                    and 0 <= confidence <= 1
                )
            )
        else:
            custody.require(
                raw["ai_run_id"] == run["id"] and raw["analysis_job_id"] == run["analysis_job_id"]
            )
            _, bundles = custody.materialize_historical_run(run)
            bundle = next(b for b in bundles if b.candidate.candidate_id == checked["candidate_id"])
            artifact_type = raw["artifact_type"]
            custody.require(artifact_type in ("SPLUNK_HUNT", "SPLUNK_DETECTION", "MISP_DRAFT"))
            if artifact_type == "MISP_DRAFT":
                expected = _misp_content(
                    assessment=CandidateAssessment.model_validate(checked["assessment"]),
                    bundle=bundle,
                    ai_run_id=run["id"],
                    analysis_job_id=run["analysis_job_id"],
                )
            else:
                expected = _splunk_content(
                    bundle=bundle,
                    detection=artifact_type == "SPLUNK_DETECTION",
                    profile=SplunkDataProfile(),
                )
            custody.require(
                raw["content"] == expected
                and raw["schema_version"] == "1.0"
                and raw["validation_status"] == "VALID"
            )
            status = raw["approved_status"]
            custody.require(status in ("PENDING", "APPROVED", "REJECTED"))
            if status != "PENDING":
                custody._identifier(raw["approved_by"])
                custody._identifier(raw["approved_at"])
            for key in ("approved_by", "reviewed_by", "created_by"):
                if key in raw:
                    custody._identifier(raw[key])
            if "review_note" in raw:
                custody.require(type(raw["review_note"]) is str and len(raw["review_note"]) <= 2000)
        return _mark(raw, checked)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, StopIteration):
        raise custody.HistoricalStorageError() from None


def reconcile(kind: str, existing: dict[str, Any], proposed: dict[str, Any]) -> dict[str, Any]:
    if kind != "T":
        custody.require(existing == proposed)
        return existing
    mutable = {"approved_status", "approved_by", "approved_at", "review_note"}
    custody.require(
        {k: v for k, v in existing.items() if k not in mutable}
        == {k: v for k, v in proposed.items() if k not in mutable}
    )
    if existing["approved_status"] != "PENDING":
        # A deterministic worker retry may restore a missing draft, never reset review.
        custody.require(proposed["approved_status"] in ("PENDING", existing["approved_status"]))
        return existing
    return proposed


def confirm_descendant(
    kind: str, expected: dict[str, Any], connect: Any, *, postgres: bool
) -> None:
    from contextlib import closing

    from .historical_ai_sql import transaction

    try:
        with closing(connect()) as connection, transaction(connection, postgres=postgres) as cursor:
            observed = SQLAccess(cursor, postgres).get(kind, expected["id"])
            custody.require(observed == expected)
    except Exception:
        raise custody.HistoricalStorageOutcomeUnknown() from None


class MemoryAccess:
    def __init__(self, repository: Any) -> None:
        self.repo = repository

    def raw(self, kind: str, identifier: Any) -> dict[str, Any] | None:
        if type(identifier) is not str:
            return None
        return getattr(self.repo, TABLES[kind][3]).get(identifier)

    def chain(
        self, kind: str, identifier: str, proposed: dict[str, Any] | None = None
    ) -> list[Meta | None]:
        raw = self.raw(kind, identifier) if proposed is None else proposed
        owner = self.repo._historical_admissions.get(identifier) if kind == "R" else None
        root = native_meta(kind, raw, identity=identifier, owner=owner)
        result = [root]
        if root is None:
            return result
        custody.require(not root.invalid)
        if kind == "R":
            return result
        parent_kind = "R" if kind == "A" else "A"
        parent_key = TABLES[kind][2]
        if raw is None:
            raise custody.HistoricalStorageError()
        # Unbounded legacy IDs are used only as native map keys, never copied/encoded.
        parent_id = raw.get(parent_key)
        parent = self.raw(parent_kind, parent_id)
        if parent is None:
            result.append(None)
        else:
            result.extend(self.chain(parent_kind, cast(str, parent_id)))
        if kind == "T":
            run_id = raw.get("ai_run_id")
            result.append(
                native_meta(
                    "R",
                    self.raw("R", run_id),
                    identity=run_id,
                    owner=self.repo._historical_admissions.get(run_id)
                    if type(run_id) is str
                    else None,
                )
            )
        return result

    def get(self, kind: str, identifier: str) -> dict[str, Any] | None:
        nodes = self.chain(kind, identifier)
        historical = guard(nodes)
        raw = self.raw(kind, identifier)
        if historical and raw is not None:
            admit_body(raw, CAPS[kind])
            if kind == "A":
                raw = checked_assessment(raw, self.run(raw["ai_run_id"]))
            else:
                assessment = self.get("A", raw["assessment_id"])
                if assessment is None:
                    raise custody.HistoricalStorageError()
                raw = checked_child(kind, raw, assessment, self.run(assessment["ai_run_id"]))
        return deepcopy(raw) if raw is not None else None

    def run(self, run_id: str) -> dict[str, Any]:
        value = custody.memory_internal(
            self.repo.ai_runs,
            self.repo._historical_admissions,
            self.repo.ai_run_idempotency_keys,
            run_id,
        )
        if value is None:
            raise custody.HistoricalStorageError()
        return value

    def save(self, kind: str, proposed: dict[str, Any]) -> dict[str, Any]:
        nodes = self.chain(kind, proposed["id"], proposed)
        old_nodes = self.chain(kind, proposed["id"])
        historical = guard(nodes + ([n for n in old_nodes if n is not None]))
        existing = self.raw(kind, proposed["id"])
        saved = proposed
        if historical:
            admit_body(proposed, CAPS[kind])
            for node in nodes:
                if node is not None and node.kind == "R":
                    custody.require(node.fields["analysis_job_id"] in self.repo.jobs)
            if kind == "A":
                run = self.run(proposed["ai_run_id"])
                saved = checked_assessment(proposed, run)
            else:
                assessment = self.get("A", proposed["assessment_id"])
                if assessment is None:
                    raise custody.HistoricalStorageError()
                run = self.run(assessment["ai_run_id"])
                saved = checked_child(kind, proposed, assessment, run)
            custody.require(run["status"] not in {"FAILED", "CANCELLED"})
            custody.require(kind != "A" or existing is not None or run["status"] != "COMPLETED")
            if existing is not None:
                previous = self.get(kind, proposed["id"])
                if previous is None:
                    raise custody.HistoricalStorageError()
                saved = reconcile(kind, previous, saved)
            admit_body(saved, CAPS[kind])
        if existing is None or kind == "T":
            getattr(self.repo, TABLES[kind][3])[saved["id"]] = deepcopy(saved)
        observed = self.get(kind, saved["id"])
        if observed is None:
            raise custody.HistoricalStorageError()
        return observed

    def list(self, kind: str, parent_id: str) -> list[dict[str, Any]]:
        parent_kind = "R" if kind == "A" else "A"
        guard(self.chain(parent_kind, parent_id))
        key = TABLES[kind][2]
        rows = [
            (identifier, raw)
            for identifier, raw in getattr(self.repo, TABLES[kind][3]).items()
            if raw.get(key) == parent_id
        ]
        for identifier, _ in rows:
            guard(self.chain(kind, identifier))
        order = (
            (lambda item: (item[1]["created_at"], item[1]["artifact_type"]))
            if kind == "T"
            else (lambda item: item[1]["created_at"])
        )
        return [
            cast(dict[str, Any], self.get(kind, identifier))
            for identifier, _ in sorted(rows, key=order)
        ]


class SQLAccess:
    """Private cursor primitives: caller owns lock, transaction and snapshot."""

    def __init__(self, cursor: Any, postgres: bool) -> None:
        from ._baseline_storage import _SQL

        self.cursor, self.postgres = cursor, postgres
        self.sql = _SQL(cursor, postgres)

    def execute(self, statement: str, values: tuple[Any, ...] = ()) -> Any:
        return self.sql.execute(statement, values)

    def _value(self, data: str, key: str) -> str:
        if self.postgres:
            return f"({data}->>'{key}')"
        # Only _meta/chain call this: expressions and JSON keys are code-owned.
        return f"(SELECT value FROM json_each({data}) WHERE key='{key}' LIMIT 1)"  # noqa: S608 -- code-owned expression/key, never row values

    def _type(self, data: str, key: str) -> str:
        if self.postgres:
            return f"jsonb_typeof({data}->'{key}')"
        return f"(SELECT type FROM json_each({data}) WHERE key='{key}' LIMIT 1)"  # noqa: S608 -- same closed expression/key callers as _value

    def _object(self, data: str, key: str) -> str:
        typ = self._type(data, key)
        value = f"({data}->'{key}')" if self.postgres else self._value(data, key)
        return f"(CASE WHEN {typ}='object' THEN {value} ELSE '{{}}' END)"

    def _length(self, value: str) -> str:
        return f"octet_length({value})" if self.postgres else f"length(CAST({value} AS BLOB))"

    def _meta(
        self, kind: str, alias: str, source: str, where: str, values: tuple[Any, ...]
    ) -> Meta | None:
        from .historical_ai_sql import COLUMNS, _shape

        _, pk, parent, _ = TABLES[kind]
        original = alias + ".data"
        data = (
            f"(CASE WHEN jsonb_typeof({original})='object' THEN {original} ELSE '{{}}'::jsonb END)"
            if self.postgres
            else f"(CASE WHEN json_valid({original}) THEN {original} ELSE '{{}}' END)"
        )
        keys = ",".join("'" + k + "'" for k in sorted(custody.PRIVATE_FIELDS))
        relevant = ",".join("'" + k + "'" for k in sorted(RELEVANT))
        bad = (
            [f"jsonb_typeof({original}) IS DISTINCT FROM 'object'"]
            if self.postgres
            else [
                f"NOT json_valid({original})",
                f"json_type({data})<>'object'",
                f"EXISTS(SELECT 1 FROM json_each({data}) WHERE key IN ({relevant}) "  # noqa: S608 -- local expression and constant RELEVANT keys
                "GROUP BY key HAVING count(*)>1)",
            ]
        )
        private = [
            f"EXISTS(SELECT 1 FROM jsonb_object_keys({data}) k WHERE k IN ({keys}))"  # noqa: S608 -- local expression and constant PRIVATE_FIELDS keys
            if self.postgres
            else f"EXISTS(SELECT 1 FROM json_each({data}) WHERE key IN ({keys}))"  # noqa: S608 -- local expression and constant PRIVATE_FIELDS keys
        ]
        text_kind = "string" if self.postgres else "text"
        typ, value = self._type(data, "baseline_mode"), self._value(data, "baseline_mode")
        mode = (
            f"CASE WHEN {typ} IS NULL THEN 0 "
            f"WHEN {typ}='{text_kind}' AND {value}='off' THEN 1 "
            f"WHEN {typ}='{text_kind}' AND {value}='historical' THEN 2 ELSE -1 END"
        )
        bad.append(f"({mode})=-1")
        for key, leaves in (
            ("baseline_summary", ("mode", "scope_kind")),
            ("baseline_request", ("baseline_mode",)),
            ("evidence_bundle", ("historical_reference",)),
        ):
            typ = self._type(data, key)
            obj = self._object(data, key)
            bad.append(f"({typ} IS NOT NULL AND {typ}<>'object')")
            if not self.postgres:
                leafkeys = ",".join("'" + k + "'" for k in leaves)
                bad.append(
                    f"EXISTS(SELECT 1 FROM json_each({obj}) WHERE key IN ({leafkeys}) "  # noqa: S608 -- _object expression and literal leaves tuple
                    "GROUP BY key HAVING count(*)>1)"
                )
            if key == "baseline_summary":
                bad.append(
                    f"({typ}='object' AND (COALESCE({self._value(obj, 'mode')},'')<>'historical' "
                    f"OR COALESCE({self._value(obj, 'scope_kind')},'') "
                    "NOT IN ('OPERATIONAL','EVALUATION')))"
                )
            elif key == "baseline_request":
                bad.append(
                    f"({typ}='object' AND "
                    f"COALESCE({self._value(obj, 'baseline_mode')},'')<>'historical')"
                )
            else:
                ref_type = self._type(obj, "historical_reference")
                private.append(f"({ref_type} IS NOT NULL AND {ref_type}<>'null')")
                bad.append(f"({ref_type} IS NOT NULL AND {ref_type} NOT IN ('null','object'))")
        if kind == "R":
            for key in ("candidate_snapshots", "selection_inventory"):
                array = (
                    (
                        f"(CASE WHEN {self._type(data, key)}='array' "
                        f"THEN {data}->'{key}' ELSE '[]'::jsonb END)"
                    )
                    if self.postgres
                    else (
                        f"(CASE WHEN {self._type(data, key)}='array' "
                        f"THEN {self._value(data, key)} ELSE '[]' END)"
                    )
                )
                members = (
                    f"jsonb_array_elements({array}) member"
                    if self.postgres
                    else f"json_each({array}) member"
                )
                obj = (
                    (
                        "(CASE WHEN jsonb_typeof(member.value)='object' "
                        "THEN member.value ELSE '{}'::jsonb END)"
                    )
                    if self.postgres
                    else "(CASE WHEN member.type='object' THEN member.value ELSE '{}' END)"
                )
                rt = self._type(obj, "historical_reference")
                private.append(
                    f"EXISTS(SELECT 1 FROM {members} WHERE {rt} IS NOT NULL AND {rt}<>'null')"  # noqa: S608 -- local array/type expressions, never JSON contents
                )
                bad.append(
                    f"EXISTS(SELECT 1 FROM {members} WHERE {rt} IS NOT NULL "  # noqa: S608 -- local array/type expressions, never JSON contents
                    f"AND {rt} NOT IN ('null','object'))"
                )
                if not self.postgres:
                    bad.append(
                        f"EXISTS(SELECT 1 FROM {members} WHERE (SELECT count(*) "  # noqa: S608 -- local array/object expressions only
                        f"FROM json_each({obj}) WHERE key='historical_reference')>1)"
                    )
        fields = []
        for key in IDENTITIES:
            val, typ = self._value(data, key), self._type(data, key)
            fields.append(
                f"CASE WHEN {typ}='{text_kind}' AND length({val}) BETWEEN 1 AND 200 "
                f"AND {self._length(val)}<=800 THEN {val} END"
            )
        own = "FALSE"
        if kind == "R":
            own = "(" + " OR ".join(f"{alias}.{col} IS NOT NULL" for col in COLUMNS) + ")"
            bad.extend(
                [f"NOT ({_shape(alias + '.', postgres=self.postgres)})", f"({own} AND ({mode})<>2)"]
            )
        equality = [f"{self._value(data, 'id')}={alias}.{pk}"]
        if parent:
            equality.append(f"{self._value(data, parent)}={alias}.{parent}")
        if kind == "R":
            equality.extend(
                f"{self._value(data, k)}={alias}.{k}"
                for k in ("analysis_job_id", "idempotency_key")
            )
        if not self.postgres:
            equality.append(f"{self._value(data, 'created_at')}={alias}.created_at")
        created = (
            f"to_char({alias}.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
            if self.postgres
            else "NULL"
        )
        length = self._length(original + "::text" if self.postgres else original)
        row = self.execute(
            f"SELECT {alias}.{pk} IS NOT NULL,"
            + ",".join(fields)
            + f",({mode}),COALESCE(({' OR '.join(private)}),FALSE),"
            f"COALESCE(({' OR '.join(bad)}),FALSE),"
            f"COALESCE(({' AND '.join(equality)}),FALSE),{own},{length},{created} "
            f"FROM {source} WHERE {where}",
            values,
        ).fetchone()
        if row is None or not row[0]:
            return None
        mode, private_flag, bad_flag, identity_ok, owner, size, created_at = row[8:]
        return Meta(
            kind,
            dict(zip(IDENTITIES, row[1:8], strict=True)),
            mode,
            bool(private_flag or owner or mode == 2),
            bool(bad_flag),
            bool(identity_ok),
            bool(owner),
            size,
            created_at,
        )

    def chain(self, kind: str, identifier: Any, *, locator: bool = False) -> list[Meta | None]:
        table, pk, _, _ = TABLES[kind]
        selector = ("ctid=?::tid" if self.postgres else "rowid=?") if locator else f"{pk}=?"
        source, where = f"{table} n0", f"n0.{selector}"
        values = (identifier,)
        root = self._meta(kind, "n0", source, where, values)
        result = [root]
        if root is None:
            return result
        custody.require(not root.invalid)
        if kind in ("T", "F"):
            source += " LEFT JOIN ai_candidate_assessments n1 ON n0.assessment_id=n1.assessment_id"
            result.append(self._meta("A", "n1", source, where, values))
            source += " LEFT JOIN ai_analysis_runs n2 ON n1.ai_run_id=n2.run_id"
            result.append(self._meta("R", "n2", source, where, values))
            if kind == "T":
                # Native server-side join: even oversized legacy IDs are never transferred.
                source += (
                    " LEFT JOIN ai_analysis_runs n3 ON "
                    + self._value("n0.data", "ai_run_id")
                    + "=n3.run_id"
                )
                result.append(self._meta("R", "n3", source, where, values))
        elif kind == "A":
            source += " LEFT JOIN ai_analysis_runs n1 ON n0.ai_run_id=n1.run_id"
            result.append(self._meta("R", "n1", source, where, values))
        return result

    def get(self, kind: str, identifier: Any, *, locator: bool = False) -> dict[str, Any] | None:
        nodes = self.chain(kind, identifier, locator=locator)
        historical = guard(nodes)
        if nodes[0] is None:
            return None
        if historical:
            custody.require(nodes[0].size <= CAPS[kind])
        table, pk, _, _ = TABLES[kind]
        selector = ("ctid=?::tid" if self.postgres else "rowid=?") if locator else f"{pk}=?"
        row = self.execute(
            f"SELECT data FROM {table} WHERE {selector}",  # noqa: S608 -- TABLES whitelist and fixed PK/rowid/ctid selector; identity bound
            (identifier,),
        ).fetchone()
        custody.require(row is not None)
        if historical:
            from .historical_read import _decode

            try:
                raw = row[0] if type(row[0]) is dict else _decode(row[0], max_bytes=CAPS[kind])
            except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
                raise custody.HistoricalStorageError() from None
            admit_body(raw, CAPS[kind])
            if kind == "A":
                return checked_assessment(raw, self.run(raw["ai_run_id"]))
            assessment = self.get("A", raw["assessment_id"])
            if assessment is None:
                raise custody.HistoricalStorageError()
            return checked_child(kind, raw, assessment, self.run(assessment["ai_run_id"]))
        return row[0] if type(row[0]) is dict else json.loads(row[0])

    def run(self, run_id: str) -> dict[str, Any]:
        from .historical_ai_sql import RunSQL

        value = RunSQL(self.cursor, self.postgres).get("run_id=?", (run_id,))
        if value is None:
            raise custody.HistoricalStorageError()
        return value

    def proposed_chain(self, kind: str, proposed: dict[str, Any]) -> list[Meta | None]:
        root = native_meta(kind, proposed, identity=proposed["id"])
        parent_kind = "R" if kind == "A" else "A"
        parent_key = TABLES[kind][2]
        custody.require(parent_key is not None)
        parent_id = proposed.get(parent_key)
        # Submitted relationships must be bounded before issuing queries.
        custody.require(type(parent_id) is str)
        nodes = [root] + self.chain(parent_kind, cast(str, parent_id))
        if kind == "T":
            nodes += self.chain("R", proposed.get("ai_run_id", ""))
        return nodes

    def save(self, kind: str, proposed: dict[str, Any]) -> dict[str, Any]:
        if self.postgres:
            self.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('pcap-export-admission',0))"
            )
        nodes = self.proposed_chain(kind, proposed)
        old_nodes = self.chain(kind, proposed["id"])
        historical = guard(nodes + [n for n in old_nodes if n is not None])
        if historical:
            job_ids = sorted(
                {
                    cast(str, n.fields["analysis_job_id"])
                    for n in nodes + old_nodes
                    if n and n.kind == "R"
                }
            )
            for job_id in job_ids:
                custody.require(
                    self.execute(
                        "SELECT id FROM controller_objects WHERE kind='job' AND id=? FOR UPDATE"
                        if self.postgres
                        else "SELECT id FROM objects WHERE kind='job' AND id=?",
                        (job_id,),
                    ).fetchone()
                    is not None
                )
        if historical and self.postgres:
            locks = {
                "R": "SELECT run_id FROM ai_analysis_runs WHERE run_id=? FOR UPDATE",
                "A": (
                    "SELECT assessment_id FROM ai_candidate_assessments "
                    "WHERE assessment_id=? FOR UPDATE"
                ),
                "T": (
                    "SELECT artifact_id FROM ai_generated_artifacts WHERE artifact_id=? FOR UPDATE"
                ),
                "F": "SELECT feedback_id FROM ai_feedback WHERE feedback_id=? FOR UPDATE",
            }
            for level in ("R", "A", "T", "F"):
                for identifier in sorted(
                    {cast(str, n.fields["id"]) for n in nodes + old_nodes if n and n.kind == level}
                ):
                    self.execute(locks[level], (identifier,)).fetchone()
            custody.require(
                self.proposed_chain(kind, proposed) == nodes
                and self.chain(kind, proposed["id"]) == old_nodes
            )
        existing = self.get(kind, proposed["id"])
        saved = proposed
        if historical:
            admit_body(proposed, CAPS[kind])
            if kind == "A":
                run = self.run(proposed["ai_run_id"])
                saved = checked_assessment(proposed, run)
            else:
                assessment = self.get("A", proposed["assessment_id"])
                if assessment is None:
                    raise custody.HistoricalStorageError()
                run = self.run(assessment["ai_run_id"])
                saved = checked_child(kind, proposed, assessment, run)
            custody.require(run["status"] not in {"FAILED", "CANCELLED"})
            custody.require(kind != "A" or existing is not None or run["status"] != "COMPLETED")
            if existing is not None:
                saved = reconcile(kind, existing, saved)
            admit_body(saved, CAPS[kind])
        table, pk, parent, _ = TABLES[kind]
        text = json.dumps(saved, separators=(",", ":"), default=str)
        conflict = "DO UPDATE SET data=excluded.data" if kind == "T" else "DO NOTHING"
        self.execute(
            f"INSERT INTO {table}({pk},{parent},created_at,data) VALUES(?,?,?,?"
            + ("::jsonb" if self.postgres else "")
            + f") ON CONFLICT({pk}) {conflict}",
            (saved["id"], saved[parent], saved["created_at"], text),
        )
        if self.postgres and kind == "A":
            from datetime import UTC, datetime

            self.execute(
                "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                "VALUES('ai-assessment',?,?,?::jsonb)",
                (saved["id"], datetime.now(UTC), text),
            )
        observed = self.get(kind, saved["id"])
        if observed is None:
            raise custody.HistoricalStorageError()
        custody.require(not historical or observed == saved)
        if not historical and (kind in {"T", "F"} or self.postgres):
            # Preserve legacy adapter return values on ignored duplicate inserts.
            return deepcopy(proposed)
        return observed

    def list(self, kind: str, parent_id: str) -> list[dict[str, Any]]:
        guard(self.chain("R" if kind == "A" else "A", parent_id))
        table, pk, parent, _ = TABLES[kind]
        locator = "ctid::text" if self.postgres else "rowid"
        ids = self.execute(
            f"SELECT {locator} FROM {table} WHERE {parent}=? ORDER BY created_at,{pk}",  # noqa: S608 -- TABLES whitelist, fixed locator; parent ID bound
            (parent_id,),
        ).fetchall()
        # Only native fixed-size row locators precede metadata classification.
        for row in ids:
            guard(self.chain(kind, row[0], locator=True))
        return [value for row in ids if (value := self.get(kind, row[0], locator=True)) is not None]
