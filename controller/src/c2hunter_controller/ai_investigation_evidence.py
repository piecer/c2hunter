"""Deterministic read-only tools over one admitted, detached source snapshot."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import cast

from .ai_investigation_contract import (
    CohortPeer,
    Counts,
    Evidence,
    InvestigationError,
    InvestigationScope,
    Metric,
    MetricName,
    MetricUnit,
    Observation,
    ProtocolObservation,
    RowReference,
    Sample,
    SourceSnapshot,
    TimelineBucket,
    ToolName,
    canonical_bytes,
    digest,
)


class EvidenceService:
    def resolve_metric(self, ref: str) -> Metric:
        if type(ref) is not str or len(ref) > 128:
            raise InvestigationError("REFERENCE_MISMATCH")
        for evidence in self._cache.values():
            for metric in evidence.metrics:
                if metric.ref == ref:
                    return metric
        raise InvestigationError("REFERENCE_MISMATCH")

    def resolve_row(self, ref: RowReference) -> Observation:
        ref = RowReference.model_validate(ref)
        if ref.source_sha256 != self.snapshot.binding.source_sha256:
            raise InvestigationError("REFERENCE_MISMATCH")
        if ref.ordinal >= len(self.snapshot.rows):
            raise InvestigationError("REFERENCE_MISMATCH")
        row = self.snapshot.rows[ref.ordinal]
        if row.row_sha256 != ref.row_sha256 or not self._matches(row):
            raise InvestigationError("REFERENCE_MISMATCH")
        return row

    def validate_evidence(self, evidence: Evidence) -> Evidence:
        if evidence.source != self.snapshot.binding or evidence.scope != self.scope:
            raise InvestigationError("REFERENCE_MISMATCH")
        expected = self.call(
            evidence.tool, {} if evidence.limit is None else {"limit": evidence.limit}
        )
        if evidence != expected:
            raise InvestigationError("REFERENCE_MISMATCH")
        return expected

    def __init__(self, snapshot: SourceSnapshot, scope: InvestigationScope) -> None:
        self.snapshot = SourceSnapshot.model_validate(snapshot)
        self.scope = InvestigationScope.model_validate(scope)
        self._prepare_rows()

    @classmethod
    def _from_prepared(cls, snapshot: SourceSnapshot, scope: InvestigationScope) -> EvidenceService:
        """Private broker seam: caller owns one validated immutable preparation.

        Public construction still detaches/revalidates arbitrary model instances.
        This is not an admission API and must never accept raw persisted input.
        """
        instance = cls.__new__(cls)
        instance.snapshot = snapshot
        instance.scope = InvestigationScope.model_validate(scope)
        instance._prepare_rows()
        return instance

    def _prepare_rows(self) -> None:
        self._cache: dict[str, Evidence] = {}
        self.retained_bytes = 0
        self._rows = tuple(row for row in self.snapshot.rows if self._matches(row))
        self._scope_unavailable = tuple(
            row
            for row in self.snapshot.rows
            if self._base_matches(row) and self._direction_matches(row) is None
        )

    def _matches(self, row: Observation) -> bool:
        return self._base_matches(row) and self._direction_matches(row) is True

    def _direction_matches(self, row: Observation) -> bool | None:
        direction = self.scope.traffic_direction
        if direction is None:
            return True
        if "direction" in row.unavailable_fields or (
            row.direction == "UNKNOWN" and direction != "UNKNOWN"
        ):
            return None
        return direction == row.direction

    def _base_matches(self, row: Observation) -> bool:
        scope = self.scope
        return (
            (scope.sensor_id is None or scope.sensor_id == row.sensor_id)
            and (scope.start_time is None or row.timestamp >= scope.start_time)
            and (scope.end_time is None or row.timestamp <= scope.end_time)
            and (
                (scope.endpoint_side != "destination" and scope.target_ip == row.source_ip)
                or (scope.endpoint_side != "source" and scope.target_ip == row.destination_ip)
            )
        )

    def _timeline(self, limit: int) -> tuple[TimelineBucket, ...]:
        if not self._rows:
            return ()
        origin = min(datetime.fromisoformat(row.timestamp) for row in self._rows)
        end = max(datetime.fromisoformat(row.timestamp) for row in self._rows)
        width = max(1, int((end - origin).total_seconds() * 1_000_000) // limit + 1)
        groups: dict[tuple[str, int], list[Observation]] = defaultdict(list)
        for row in self._rows:
            offset = datetime.fromisoformat(row.timestamp) - origin
            micros = (offset.days * 86400 + offset.seconds) * 1_000_000 + offset.microseconds
            groups[row.sensor_id, micros // width].append(row)
        result = []
        for key in sorted(groups)[:limit]:
            rows = groups[key]
            packet = sum(r.packet_count == 1 and r.duration_seconds == 0 for r in rows)
            unavailable = sum(r.packet_count is None or r.duration_seconds is None for r in rows)
            result.append(
                TimelineBucket(
                    sensor_id=key[0],
                    start_time=min(r.timestamp for r in rows),
                    end_time=max(r.timestamp for r in rows),
                    rows=len(rows),
                    packet_rows=packet,
                    unavailable_rows=unavailable,
                    aggregate_rows=len(rows) - packet - unavailable,
                )
            )
        return tuple(result)

    def _cohort(self, limit: int) -> tuple[tuple[CohortPeer, ...], int, int]:
        target_streams = {(r.sensor_id, r.protocol) for r in self._rows if self._known_protocol(r)}
        possible_rows = self._rows + self._scope_unavailable
        target_sensors = {r.sensor_id for r in possible_rows}
        possible_streams = {
            (r.sensor_id, r.protocol) for r in possible_rows if self._known_protocol(r)
        }
        uncertain_sensors = {r.sensor_id for r in possible_rows if not self._known_protocol(r)}
        unavailable = 0
        groups: dict[tuple[str, str], list[Observation]] = defaultdict(list)
        scope = self.scope
        for row in self.snapshot.rows:
            if (
                row.sensor_id not in target_sensors
                or (scope.start_time is not None and row.timestamp < scope.start_time)
                or (scope.end_time is not None and row.timestamp > scope.end_time)
                or self._direction_matches(row) is False
            ):
                continue
            stream = (row.sensor_id, row.protocol)
            if (
                self._known_protocol(row)
                and stream not in possible_streams
                and row.sensor_id not in uncertain_sensors
            ):
                continue
            if (
                not self._known_protocol(row)
                or stream not in target_streams
                or self._direction_matches(row) is None
            ):
                unavailable += 1
                continue
            for ip in sorted({row.source_ip, row.destination_ip} - {scope.target_ip}):
                groups[row.sensor_id, ip].append(row)
        peers = []
        for sensor, ip in sorted(groups)[:limit]:
            rows = groups[sensor, ip]
            observed = sum(r.total_bytes is not None for r in rows)
            peers.append(
                CohortPeer(
                    sensor_id=sensor,
                    ip=ip,
                    rows=len(rows),
                    total_bytes=sum(r.total_bytes for r in rows if r.total_bytes is not None)
                    if observed == len(rows)
                    else None,
                    observed_byte_rows=observed,
                )
            )
        return tuple(peers), len(groups), unavailable

    @staticmethod
    def _known_protocol(row: Observation) -> bool:
        # OTHER is a category, never proof of equal actual protocols.
        return row.protocol != "OTHER" and "protocol" not in row.unavailable_fields

    def call(self, tool: str, arguments: object) -> Evidence:
        if (
            type(arguments) is not dict
            or len(arguments) > 1
            or tool
            not in (
                "peer_overview",
                "peer_flow_samples",
                "peer_timeline",
                "peer_protocol_observations",
                "compare_peer_cohort",
            )
        ):
            raise InvestigationError("INVALID_TOOL_ARGUMENTS")
        limit = None
        if tool == "peer_overview" and arguments:
            raise InvestigationError("INVALID_TOOL_ARGUMENTS")
        if tool != "peer_overview":
            maximum = {"peer_timeline": 120, "compare_peer_cohort": 20}.get(tool, 50)
            limit = arguments.get("limit", maximum)
            if set(arguments) - {"limit"} or type(limit) is not int or not 1 <= limit <= maximum:
                raise InvestigationError("INVALID_TOOL_ARGUMENTS")
            arguments = {"limit": limit}
        rows = self._rows
        scope_unavailable = len(self._scope_unavailable)
        identity = digest(
            [self.snapshot.binding.source_sha256, self.scope.model_dump(), tool, arguments]
        )
        if identity in self._cache:
            return self._cache[identity]
        metrics = []
        specs: tuple[tuple[MetricName, MetricUnit], ...] = (
            ("matched_rows", "rows"),
            ("total_bytes", "bytes"),
            ("packet_count", "packets"),
            ("sensor_count", "sensors"),
        )
        for name, unit in specs:
            values = (
                [getattr(row, name) for row in rows]
                if name in ("total_bytes", "packet_count")
                else []
            )
            observed = sum(value is not None for value in values) if values else len(rows)
            value = sum(v for v in values if v is not None) if observed == len(rows) else None
            if name == "matched_rows":
                value = len(rows)
            if name == "sensor_count":
                value = len({row.sensor_id for row in rows})
            metrics.append(
                Metric(
                    ref=f"{identity}:{name}",
                    name=name,
                    unit=unit,
                    value=None if scope_unavailable else value,
                    observed_rows=observed,
                    unavailable_rows=len(rows) - observed + scope_unavailable,
                )
            )
        eligibility_specs: tuple[tuple[MetricName, str], ...] = (
            ("c2_eligible_rows", "ELIGIBLE"),
            ("suppressed_control_rows", "SUPPRESSED_OUTBOUND_CONTROL"),
            ("eligibility_unavailable_rows", "UNAVAILABLE"),
        )
        for name, eligibility in eligibility_specs:
            metrics.append(
                Metric(
                    ref=f"{identity}:{name}",
                    name=name,
                    unit="rows",
                    value=None
                    if scope_unavailable
                    else sum(r.c2_eligibility == eligibility for r in rows),
                    observed_rows=len(rows),
                    unavailable_rows=scope_unavailable,
                )
            )
        for direction in ("INBOUND", "OUTBOUND", "INTERNAL", "UNKNOWN"):
            selected = [r for r in rows if r.direction == direction]
            uncertain = scope_unavailable if self.scope.traffic_direction == direction else 0
            if self.scope.traffic_direction is None and direction != "UNKNOWN":
                # UNKNOWN remains a counted projection category, but cannot prove
                # the absence (or exact total) of any known traffic direction.
                uncertain += sum(r.direction == "UNKNOWN" for r in rows)
            observed_bytes = sum(r.total_bytes is not None for r in selected)
            for suffix, unit in (("rows", "rows"), ("bytes", "bytes")):
                name = cast(MetricName, direction.lower() + "_" + suffix)
                measured = len(selected) if suffix == "rows" else observed_bytes
                number = (
                    len(selected)
                    if suffix == "rows"
                    else (
                        sum(r.total_bytes for r in selected if r.total_bytes is not None)
                        if measured == len(selected)
                        else None
                    )
                )
                metrics.append(
                    Metric(
                        ref=f"{identity}:{name}",
                        name=name,
                        unit=cast(MetricUnit, unit),
                        value=None if uncertain else number,
                        observed_rows=measured,
                        unavailable_rows=len(selected) - measured + uncertain,
                    )
                )
        timeline = self._timeline(limit) if tool == "peer_timeline" and limit is not None else ()
        retained = len(rows) if limit is None else min(len(rows), limit)
        if tool == "peer_timeline":
            retained = sum(bucket.rows for bucket in timeline)
        protocols: tuple[ProtocolObservation, ...] = ()
        unavailable = 0
        if tool == "peer_protocol_observations":
            protocol_rows = [
                r
                for r in rows
                if any(
                    getattr(r, key) is not None
                    for key in (
                        "domain",
                        "tls_fingerprint",
                        "certificate_fingerprint",
                        "payload_length",
                        "tcp_flags",
                    )
                )
            ]
            unavailable = len(rows) - len(protocol_rows)
            protocols = tuple(
                ProtocolObservation(
                    ref=RowReference(
                        source_sha256=self.snapshot.binding.source_sha256,
                        ordinal=r.ordinal,
                        row_sha256=r.row_sha256,
                    ),
                    domain=r.domain,
                    tls_fingerprint=r.tls_fingerprint,
                    certificate_fingerprint=r.certificate_fingerprint,
                    payload_length=r.payload_length,
                    payload_length_source=r.payload_length_source,
                    tcp_flags=r.tcp_flags,
                    c2_eligibility=r.c2_eligibility,
                )
                for r in protocol_rows[:limit]
            )
            retained = len(protocols)
        cohort, cohort_total, cohort_unavailable = (
            self._cohort(limit) if tool == "compare_peer_cohort" and limit else ((), 0, 0)
        )
        if tool == "compare_peer_cohort":
            retained = len(rows)
        evidence = Evidence(
            evidence_id=identity,
            source=self.snapshot.binding,
            scope=self.scope,
            tool=cast(ToolName, tool),
            args_sha256=digest(arguments),
            limit=limit,
            status=(
                "UNAVAILABLE"
                if (rows and unavailable == len(rows))
                or (cohort_unavailable and not cohort)
                or (scope_unavailable and not rows)
                else "OBSERVED"
                if rows
                else "NOT_FOUND_IN_INSPECTED_SCOPE"
                if self.snapshot.status == "PARTIALLY_COMPLETED"
                else "NOT_OBSERVED"
            ),
            counts=Counts(
                inspected=len(self.snapshot.rows),
                matched=len(rows),
                retained=retained,
                omitted=len(rows) - retained - unavailable,
                unavailable=unavailable,
                not_observed=len(self.snapshot.rows) - len(rows) - scope_unavailable,
                scope_unavailable=scope_unavailable,
            ),
            samples=()
            if tool != "peer_flow_samples"
            else tuple(
                Sample(
                    ref=RowReference(
                        source_sha256=self.snapshot.binding.source_sha256,
                        ordinal=row.ordinal,
                        row_sha256=row.row_sha256,
                    ),
                    row=row,
                    c2_eligibility=row.c2_eligibility,
                )
                for row in rows[:limit]
            ),
            timeline=timeline,
            protocols=protocols,
            metrics=tuple(metrics),
            cohort=cohort,
            cohort_total=cohort_total,
            cohort_omitted=cohort_total - len(cohort),
            cohort_unavailable_rows=cohort_unavailable,
            limitations=(
                "SENSOR_IDENTITIES_NOT_MERGED",
                "TIMING_QUALITY_UNAVAILABLE",
                "RETAINED_NORMALIZED_ROWS_ONLY",
                "CAPTURE_COMPLETENESS_UNVERIFIED",
                "CONTROL_TRAFFIC_NOT_C2_EVIDENCE",
            )
            + (("AGGREGATE_NOT_PACKET_TIMING",) if any(b.aggregate_rows for b in timeline) else ())
            + (("SIMILARITY_IS_NOT_NORMALITY",) if tool == "compare_peer_cohort" else ())
            + (("PARTIAL_SOURCE",) if self.snapshot.status == "PARTIALLY_COMPLETED" else ())
            + (
                ("SOURCE_FIELDS_UNAVAILABLE",)
                if scope_unavailable
                or cohort_unavailable
                or any(r.unavailable_fields or r.direction == "UNKNOWN" for r in rows)
                else ()
            ),
        )
        evidence = self._bounded_reply(evidence)
        size = len(canonical_bytes(evidence.model_dump(mode="json")))
        if self.retained_bytes + size > 256 * 1024:
            raise InvestigationError("EVIDENCE_BUDGET")
        self.retained_bytes += size
        self._cache[identity] = evidence
        return evidence

    @staticmethod
    def _bounded_reply(evidence: Evidence) -> Evidence:
        # Closed field/cardinality bounds keep this first encoding under 256 KiB.
        # Shrink complete typed units only; never return broken JSON or fake zeros.
        while len(canonical_bytes(evidence.model_dump(mode="json"))) > 32768:
            field = next(
                (
                    name
                    for name in ("samples", "timeline", "protocols", "cohort")
                    if getattr(evidence, name)
                ),
                None,
            )
            if field is None:
                raise InvestigationError("REPLY_LIMIT")
            units = getattr(evidence, field)
            update = {field: units[:-1]}
            if field == "cohort":
                update["cohort_omitted"] = evidence.cohort_omitted + 1
            else:
                dropped = units[-1].rows if field == "timeline" else 1
                update["counts"] = evidence.counts.model_copy(
                    update={
                        "retained": evidence.counts.retained - dropped,
                        "omitted": evidence.counts.omitted + dropped,
                    }
                )
            if "REPLY_BYTE_LIMIT" not in evidence.limitations:
                update["limitations"] = (*evidence.limitations, "REPLY_BYTE_LIMIT")
            evidence = Evidence.model_validate(evidence.model_copy(update=update))
        return evidence
