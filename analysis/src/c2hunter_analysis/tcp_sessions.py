from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from .domain import AnalysisContext, Flow
from .traffic_suppression import outbound_control_flood_flow_ids

TCPConnectionKey = tuple[str, str, str, int | None, int | None]
FlowRow = tuple[str, Flow]
MAX_SYN_RETRY_OBSERVATIONS_PER_CONNECTION = 4096
MAX_SYN_RETRY_EPISODES_PER_CONNECTION = 64
MAX_SYN_RETRY_RESPONSE_ROWS = 4096
MAX_SYN_RETRY_EVIDENCE_PER_CANDIDATE = 64
MAX_SYN_RETRY_EVIDENCE_PER_ANALYSIS = 512


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


@dataclass(frozen=True)
class TCPSYNRetryEpisode:
    sequence: int
    intervals_ms: tuple[int, ...]
    rows: tuple[Flow, ...]
    first_seen: datetime
    last_seen: datetime


def _candidate_host(context: AnalysisContext, flow: Flow) -> tuple[str, str] | None:
    direction = flow.direction.upper()
    if direction == "OUTBOUND":
        return flow.destination_ip, flow.source_ip
    if direction == "INBOUND":
        return flow.source_ip, flow.destination_ip
    if context.is_internal(flow.source_ip) and not context.is_internal(flow.destination_ip):
        return flow.destination_ip, flow.source_ip
    if context.is_internal(flow.destination_ip) and not context.is_internal(flow.source_ip):
        return flow.source_ip, flow.destination_ip
    return None


def _has_response_outcome_signal(flow: Flow) -> bool:
    return bool(
        flow.tcp_syn_ack_count
        or flow.tcp_ack_only_count
        or flow.tcp_rst_count
        or flow.bidirectional
        or flow.payload_hash
        or flow.last_payload_hash
        or flow.payload_prefix_hash
        or flow.payload_simhash
        or (flow.payload_length or 0) > 0
    )


def _raw_groups(context: AnalysisContext) -> dict[str, list[FlowRow]]:
    grouped: dict[str, list[FlowRow]] = defaultdict(list)
    for flow in context.scoped_flows():
        role = _candidate_host(context, flow)
        if role is not None:
            grouped[role[0]].append((role[1], flow))
    return grouped


def _normalized_direction(context: AnalysisContext, flow: Flow) -> str:
    direction = flow.direction.upper()
    if direction in {"OUTBOUND", "INBOUND"}:
        return direction
    source_internal = context.is_internal(flow.source_ip)
    destination_internal = context.is_internal(flow.destination_ip)
    if source_internal and not destination_internal:
        return "OUTBOUND"
    if destination_internal and not source_internal:
        return "INBOUND"
    return "UNKNOWN"


def _connection_key(context: AnalysisContext, flow: Flow) -> TCPConnectionKey | None:
    if flow.protocol.upper() != "TCP":
        return None
    role = _candidate_host(context, flow)
    if role is None:
        return None
    candidate, host = role
    direction = _normalized_direction(context, flow)
    if direction == "OUTBOUND":
        internal_port, service_port = flow.source_port, flow.destination_port
    elif direction == "INBOUND":
        internal_port, service_port = flow.destination_port, flow.source_port
    else:
        return None
    return flow.sensor_id, candidate, host, internal_port, service_port


@dataclass
class TCPConnectionProfile:
    rows: list[FlowRow] = field(default_factory=list)
    metadata_available: bool = False
    outbound_syn_only: int = 0
    inbound_syn_only: int = 0
    outbound_syn_ack: int = 0
    inbound_syn_ack: int = 0
    outbound_ack_only: int = 0
    inbound_ack_only: int = 0
    outbound_rst: int = 0
    inbound_rst: int = 0
    outbound_payload: bool = False
    inbound_payload: bool = False
    bidirectional: bool = False
    total_packets: int = 0
    syn_retry_analysis_incomplete_reason: str | None = None
    syn_retry_observations_examined: int = 0
    syn_retry_episodes_examined: int = 0
    syn_retry_response_rows_truncated: bool = False
    syn_retry_response_timing_approximate: bool = False
    _ordered_rows: tuple[FlowRow, ...] | None = field(default=None, repr=False)
    _ordered_timestamps: tuple[datetime, ...] | None = field(default=None, repr=False)
    _prefix_max_end: tuple[datetime, ...] | None = field(default=None, repr=False)
    _ordered_syn_attempts: tuple[tuple[datetime, int, int], ...] | None = field(
        default=None, repr=False
    )
    _ambiguous_episode_flow_ids: set[int] = field(default_factory=set, repr=False)
    _rows_by_id: dict[int, FlowRow] | None = field(default=None, repr=False)

    def add(self, context: AnalysisContext, row: FlowRow) -> None:
        self.rows.append(row)
        self._ordered_rows = None
        self._ordered_timestamps = None
        self._prefix_max_end = None
        self._ordered_syn_attempts = None
        self._ambiguous_episode_flow_ids.clear()
        self._rows_by_id = None
        flow = row[1]
        self.metadata_available = self.metadata_available or flow.tcp_flags_observed
        self.bidirectional = self.bidirectional or flow.bidirectional
        self.total_packets += max(0, flow.packet_count)
        direction = _normalized_direction(context, flow)
        has_payload = bool(
            flow.payload_hash
            or flow.last_payload_hash
            or flow.payload_prefix_hash
            or flow.payload_simhash
            or (flow.payload_length or 0) > 0
        )
        if direction == "OUTBOUND":
            self.outbound_syn_only += max(0, flow.tcp_syn_only_count)
            self.outbound_syn_ack += max(0, flow.tcp_syn_ack_count)
            self.outbound_ack_only += max(0, flow.tcp_ack_only_count)
            self.outbound_rst += max(0, flow.tcp_rst_count)
            self.outbound_payload = self.outbound_payload or has_payload
        elif direction == "INBOUND":
            self.inbound_syn_only += max(0, flow.tcp_syn_only_count)
            self.inbound_syn_ack += max(0, flow.tcp_syn_ack_count)
            self.inbound_ack_only += max(0, flow.tcp_ack_only_count)
            self.inbound_rst += max(0, flow.tcp_rst_count)
            self.inbound_payload = self.inbound_payload or has_payload

    @property
    def internally_initiated(self) -> bool:
        return self.outbound_syn_only > 0

    @property
    def established(self) -> bool:
        outbound_handshake = (
            self.outbound_syn_only > 0 and self.inbound_syn_ack > 0 and self.outbound_ack_only > 0
        )
        inbound_handshake = (
            self.inbound_syn_only > 0 and self.outbound_syn_ack > 0 and self.inbound_ack_only > 0
        )
        midstream_ack_exchange = self.outbound_ack_only > 0 and self.inbound_ack_only > 0
        payload_with_reply = self.bidirectional and (
            (self.outbound_payload and self.inbound_ack_only > 0)
            or (self.inbound_payload and self.outbound_ack_only > 0)
            or (self.outbound_payload and self.inbound_payload)
        )
        return (
            outbound_handshake or inbound_handshake or midstream_ack_exchange or payload_with_reply
        )

    @property
    def qualified(self) -> bool:
        return self.internally_initiated or self.established

    @property
    def outbound_syn_unanswered(self) -> bool:
        """Return whether no handshake-completion signal was observed.

        Absence is not proof of remote unavailability because capture loss and
        asymmetric visibility remain possible.
        """
        return (
            self.metadata_available
            and self.internally_initiated
            and self.inbound_syn_ack == 0
            and self.outbound_ack_only == 0
        )

    @property
    def scan_like(self) -> bool:
        return (
            self.metadata_available
            and self.inbound_syn_only > 0
            and not self.internally_initiated
            and not self.established
        )

    def external_connect_probe(self, maximum_packets: int) -> bool:
        return (
            self.metadata_available
            and self.inbound_syn_only > 0
            and not self.internally_initiated
            and self.total_packets <= maximum_packets
            and not self.outbound_payload
            and not self.inbound_payload
        )

    def periodic_syn_retries(self, context: AnalysisContext) -> tuple[TCPSYNRetryEpisode, ...]:
        self.syn_retry_analysis_incomplete_reason = None
        self.syn_retry_observations_examined = 0
        self.syn_retry_episodes_examined = 0
        self.syn_retry_response_rows_truncated = False
        self.syn_retry_response_timing_approximate = False
        self._ambiguous_episode_flow_ids.clear()
        if not bool(context.parameters.get("tcp_syn_retry_detection_enabled", True)):
            return ()
        outbound = [
            flow
            for _host, flow in sorted(self.rows, key=lambda row: row[1].timestamp)
            if _normalized_direction(context, flow) == "OUTBOUND" and flow.tcp_syn_only_count > 0
        ]
        if not outbound or any(
            flow.tcp_syn_only_observations is None
            or flow.tcp_syn_only_observations_truncated
            or len(flow.tcp_syn_only_observations) != flow.tcp_syn_only_count
            for flow in outbound
        ):
            return ()
        observation_timeline: list[tuple[datetime, int, Flow]] = []
        observation_count = 0
        for flow in outbound:
            for offset_us, sequence in flow.tcp_syn_only_observations or ():
                observation_count += 1
                self.syn_retry_observations_examined = observation_count
                if observation_count > MAX_SYN_RETRY_OBSERVATIONS_PER_CONNECTION:
                    self.syn_retry_analysis_incomplete_reason = "observation_budget_exceeded"
                    return ()
                if offset_us < 0 or not 0 <= sequence <= 2**32 - 1:
                    return ()
                observation_timeline.append(
                    (
                        flow.timestamp + timedelta(microseconds=offset_us),
                        sequence,
                        flow,
                    )
                )
        minimum_intervals = max(3, int(context.parameters.get("tcp_syn_retry_min_intervals", 3)))
        minimum_ms = max(1, int(context.parameters.get("tcp_syn_retry_min_interval_ms", 500)))
        maximum_ms = max(
            minimum_ms,
            int(context.parameters.get("tcp_syn_retry_max_interval_ms", 120_000)),
        )
        minimum_us = minimum_ms * 1000
        maximum_us = maximum_ms * 1000
        maximum_multiple = max(
            1, int(context.parameters.get("tcp_syn_retry_max_interval_multiple", 8))
        )
        tolerance_ratio = max(
            0.0,
            min(0.5, float(context.parameters.get("tcp_syn_retry_tolerance_ratio", 0.20))),
        )
        absolute_tolerance = max(
            0, int(context.parameters.get("tcp_syn_retry_absolute_tolerance_ms", 250))
        )

        def retry_intervals_us(segment: list[tuple[datetime, Flow]]) -> tuple[int, ...]:
            return tuple(
                _timedelta_microseconds(right[0] - left[0])
                for left, right in zip(segment, segment[1:], strict=False)
            )

        episodes: list[TCPSYNRetryEpisode] = []
        observation_runs: list[tuple[int, list[tuple[datetime, Flow]]]] = []
        for timestamp, sequence, flow in sorted(observation_timeline, key=lambda value: value[0]):
            if not observation_runs or observation_runs[-1][0] != sequence:
                observation_runs.append((sequence, []))
            observation_runs[-1][1].append((timestamp, flow))
        for sequence, ordered in observation_runs:
            segments: list[list[tuple[datetime, Flow]]] = [[]]
            for value in ordered:
                if segments[-1]:
                    gap_us = _timedelta_microseconds(value[0] - segments[-1][-1][0])
                    if not minimum_us <= gap_us <= maximum_us:
                        segments.append([])
                segments[-1].append(value)
            cadence_segments: list[list[tuple[datetime, Flow]]] = []
            for segment in segments:
                if not segment:
                    continue
                current = [segment[0]]
                base_us: int | None = None
                previous_multiple = 0
                for value in segment[1:]:
                    interval_us = _timedelta_microseconds(value[0] - current[-1][0])
                    if base_us is None:
                        base_us = interval_us
                        multiple = 1
                    else:
                        multiple = round(interval_us / base_us)
                    tolerance_us = max(absolute_tolerance * 1000, round(base_us * tolerance_ratio))
                    if (
                        previous_multiple <= multiple <= maximum_multiple
                        and abs(interval_us - base_us * multiple) <= tolerance_us
                    ):
                        current.append(value)
                        previous_multiple = multiple
                        continue
                    if len(current) >= minimum_intervals + 1:
                        cadence_segments.append(current)
                    current = [current[-1], value]
                    base_us = interval_us
                    previous_multiple = 1
                if len(current) >= minimum_intervals + 1:
                    cadence_segments.append(current)
            for segment in cadence_segments:
                intervals_us = retry_intervals_us(segment)
                intervals = tuple(round(interval_us / 1000) for interval_us in intervals_us)
                rows_by_id = {id(flow): flow for _timestamp, flow in segment}
                rows = tuple(rows_by_id.values())
                episodes.append(
                    TCPSYNRetryEpisode(
                        sequence,
                        intervals,
                        rows,
                        segment[0][0],
                        segment[-1][0],
                    )
                )
                self.syn_retry_episodes_examined = len(episodes)
                if len(episodes) > MAX_SYN_RETRY_EPISODES_PER_CONNECTION:
                    self.syn_retry_analysis_incomplete_reason = "episode_budget_exceeded"
                    return ()
        return tuple(sorted(episodes, key=lambda episode: episode.first_seen))

    def periodic_syn_retry(self, context: AnalysisContext) -> TCPSYNRetryEpisode | None:
        return max(
            self.periodic_syn_retries(context),
            key=lambda episode: len(episode.intervals_ms),
            default=None,
        )

    def syn_retry_rows(
        self, context: AnalysisContext, episode: TCPSYNRetryEpisode
    ) -> tuple[FlowRow, ...]:
        self.syn_retry_response_rows_truncated = False
        self.syn_retry_response_timing_approximate = False
        self._ambiguous_episode_flow_ids.clear()
        grace_ms = max(1000, min(max(episode.intervals_ms), 10_000))
        response_deadline = episode.last_seen + timedelta(milliseconds=grace_ms)
        if self._ordered_rows is None:
            self._ordered_rows = tuple(sorted(self.rows, key=lambda row: row[1].timestamp))
            self._ordered_timestamps = tuple(row[1].timestamp for row in self._ordered_rows)
            prefix_end_index: list[datetime] = []
            for row in self._ordered_rows:
                flow = row[1]
                flow_end = flow.timestamp + timedelta(seconds=max(0.0, flow.duration_seconds))
                prefix_end_index.append(
                    max(flow_end, prefix_end_index[-1]) if prefix_end_index else flow_end
                )
            self._prefix_max_end = tuple(prefix_end_index)
            self._ordered_syn_attempts = tuple(
                sorted(
                    (
                        flow.timestamp + timedelta(microseconds=offset_us),
                        sequence,
                        id(flow),
                    )
                    for _host, flow in self._ordered_rows
                    if _normalized_direction(context, flow) == "OUTBOUND"
                    for offset_us, sequence in (flow.tcp_syn_only_observations or ())
                )
            )
            self._rows_by_id = {id(row[1]): row for row in self.rows}
        ordered_rows = self._ordered_rows
        ordered_timestamps = self._ordered_timestamps or ()
        prefix_max_end = self._prefix_max_end or ()
        ordered_syn_attempts = self._ordered_syn_attempts or ()
        rows_by_id = self._rows_by_id or {}
        selected: list[FlowRow] = []
        selected_ids: set[int] = set()
        for flow in episode.rows:
            if (episode_row := rows_by_id.get(id(flow))) is not None:
                selected.append(episode_row)
                selected_ids.add(id(flow))
        next_attempt = next(
            (
                (timestamp, flow_id)
                for timestamp, sequence, flow_id in ordered_syn_attempts
                if episode.last_seen <= timestamp <= response_deadline
                and sequence != episode.sequence
            ),
            None,
        )
        if next_attempt is not None:
            response_deadline, next_attempt_flow_id = next_attempt
            if next_attempt_flow_id in selected_ids:
                self._ambiguous_episode_flow_ids.add(next_attempt_flow_id)
                self.syn_retry_response_timing_approximate = True
        for flow in episode.rows:
            flow_end = flow.timestamp + timedelta(seconds=max(0.0, flow.duration_seconds))
            crosses_boundary = flow_end > response_deadline or (
                next_attempt is not None and flow_end >= response_deadline
            )
            if crosses_boundary and _has_response_outcome_signal(flow):
                self._ambiguous_episode_flow_ids.add(id(flow))
                self.syn_retry_response_timing_approximate = True
        start = bisect_left(ordered_timestamps, episode.first_seen)
        end = (
            bisect_left(ordered_timestamps, response_deadline)
            if next_attempt is not None
            else bisect_right(ordered_timestamps, response_deadline)
        )
        inspected_response_rows = 0
        prior_index = start - 1
        while prior_index >= 0 and prefix_max_end[prior_index] >= episode.first_seen:
            if inspected_response_rows >= MAX_SYN_RETRY_RESPONSE_ROWS:
                self.syn_retry_response_rows_truncated = True
                break
            inspected_response_rows += 1
            row = ordered_rows[prior_index]
            prior_index -= 1
            flow = row[1]
            flow_end = flow.timestamp + timedelta(seconds=max(0.0, flow.duration_seconds))
            if flow_end < episode.first_seen:
                continue
            flow_id = id(flow)
            if flow_id not in selected_ids:
                selected.append(row)
                selected_ids.add(flow_id)
                self.syn_retry_response_timing_approximate = True
            if _has_response_outcome_signal(flow) and (
                flow_end > response_deadline
                or (next_attempt is not None and flow_end >= response_deadline)
            ):
                self._ambiguous_episode_flow_ids.add(flow_id)
                self.syn_retry_response_timing_approximate = True
        for row in ordered_rows[start:end]:
            flow_id = id(row[1])
            if flow_id in selected_ids:
                continue
            if inspected_response_rows >= MAX_SYN_RETRY_RESPONSE_ROWS:
                self.syn_retry_response_rows_truncated = True
                break
            inspected_response_rows += 1
            selected.append(row)
            selected_ids.add(flow_id)
            flow_end = row[1].timestamp + timedelta(seconds=max(0.0, row[1].duration_seconds))
            if _has_response_outcome_signal(row[1]) and (
                flow_end > response_deadline
                or (next_attempt is not None and flow_end >= response_deadline)
            ):
                self._ambiguous_episode_flow_ids.add(flow_id)
                self.syn_retry_response_timing_approximate = True
        return tuple(selected)

    def syn_retry_outcome(self, context: AnalysisContext, episode: TCPSYNRetryEpisode) -> str:
        scoped = TCPConnectionProfile()
        for row in self.syn_retry_rows(context, episode):
            if id(row[1]) in self._ambiguous_episode_flow_ids:
                row = (
                    row[0],
                    replace(
                        row[1],
                        payload_hash=None,
                        payload_prefix_hash=None,
                        payload_length=None,
                        payload_simhash=None,
                        last_payload_hash=None,
                        tcp_ack_count=0,
                        tcp_rst_count=0,
                        tcp_syn_ack_count=0,
                        tcp_ack_only_count=0,
                        bidirectional=False,
                    ),
                )
            scoped.add(context, row)
        if scoped.established:
            return "ESTABLISHED_OBSERVED"
        if scoped.inbound_rst > 0:
            return "REFUSED_OR_RESET_OBSERVED"
        if scoped.inbound_syn_ack > 0 or scoped.inbound_ack_only > 0 or scoped.inbound_payload:
            return "PEER_RESPONSE_OBSERVED"
        if scoped.outbound_ack_only > 0:
            return "LOCAL_ACK_OBSERVED"
        return "NO_COMPLETION_OBSERVED"


@dataclass(frozen=True)
class TCPSYNRetrySelection:
    candidate: str
    key: TCPConnectionKey
    profile: TCPConnectionProfile
    episode: TCPSYNRetryEpisode | None = None
    incomplete_reason: str | None = None


def tcp_profiles(
    context: AnalysisContext,
    rows_by_candidate: Mapping[str, list[FlowRow]] | None = None,
) -> tuple[dict[str, list[FlowRow]], dict[str, dict[TCPConnectionKey, TCPConnectionProfile]]]:
    raw = (
        {candidate: list(rows) for candidate, rows in rows_by_candidate.items()}
        if rows_by_candidate is not None
        else _raw_groups(context)
    )
    result: dict[str, dict[TCPConnectionKey, TCPConnectionProfile]] = {}
    for candidate, rows in raw.items():
        connections: dict[TCPConnectionKey, TCPConnectionProfile] = {}
        for row in rows:
            key = _connection_key(context, row[1])
            if key is None:
                continue
            connections.setdefault(key, TCPConnectionProfile()).add(context, row)
        result[candidate] = connections
    return raw, result


def bounded_syn_retry_selections(context: AnalysisContext) -> tuple[TCPSYNRetrySelection, ...]:
    """Select retry evidence under candidate- and analysis-wide output budgets."""

    _raw, profiles = tcp_profiles(context)
    selected: list[TCPSYNRetrySelection] = []
    for candidate, connections in profiles.items():
        candidate_count = 0
        candidate_complete = True
        for key, profile in connections.items():
            if key[3] is None or key[4] is None:
                continue
            episodes = profile.periodic_syn_retries(context)
            entries: tuple[tuple[TCPSYNRetryEpisode | None, str | None], ...]
            if profile.syn_retry_analysis_incomplete_reason:
                entries = ((None, profile.syn_retry_analysis_incomplete_reason),)
            else:
                entries = tuple((episode, None) for episode in episodes)
            for episode, incomplete_reason in entries:
                if len(selected) >= MAX_SYN_RETRY_EVIDENCE_PER_ANALYSIS:
                    last = selected[-1]
                    selected[-1] = TCPSYNRetrySelection(
                        last.candidate,
                        last.key,
                        last.profile,
                        incomplete_reason="analysis_evidence_budget_exceeded",
                    )
                    return tuple(selected)
                if candidate_count >= MAX_SYN_RETRY_EVIDENCE_PER_CANDIDATE:
                    selected[-1] = TCPSYNRetrySelection(
                        candidate,
                        key,
                        profile,
                        incomplete_reason="candidate_evidence_budget_exceeded",
                    )
                    candidate_complete = False
                    break
                selected.append(
                    TCPSYNRetrySelection(
                        candidate,
                        key,
                        profile,
                        episode=episode,
                        incomplete_reason=incomplete_reason,
                    )
                )
                candidate_count += 1
            if not candidate_complete:
                break
    return tuple(selected)


def scan_suppressed_keys(
    context: AnalysisContext,
    connections: Mapping[TCPConnectionKey, TCPConnectionProfile],
) -> set[TCPConnectionKey]:
    if not bool(context.parameters.get("tcp_scan_suppression_enabled", True)):
        return set()
    minimum_targets = max(2, int(context.parameters.get("tcp_scan_min_targets", 8)))
    maximum_packets = max(1, int(context.parameters.get("tcp_scan_probe_max_packets", 4)))
    minimum_ratio = max(
        0.0,
        min(1.0, float(context.parameters.get("tcp_scan_probe_ratio", 0.8))),
    )
    observed = {key: profile for key, profile in connections.items() if profile.metadata_available}
    probes = {
        key for key, profile in observed.items() if profile.external_connect_probe(maximum_packets)
    }
    targets = {key[2] for key in probes}
    if (
        len(targets) < minimum_targets
        or not observed
        or len(probes) / len(observed) < minimum_ratio
    ):
        return set()
    return probes


def _without_outbound_control_floods(
    context: AnalysisContext, raw: Mapping[str, list[FlowRow]]
) -> dict[str, list[FlowRow]]:
    retained: dict[str, list[FlowRow]] = {}
    for candidate, rows in raw.items():
        suppressed = outbound_control_flood_flow_ids(context, (flow for _host, flow in rows))
        selected = [row for row in rows if id(row[1]) not in suppressed]
        if selected:
            retained[candidate] = selected
    return retained


def syn_retry_duplicate_flow_ids(context: AnalysisContext) -> set[int]:
    duplicates: set[int] = set()
    for selection in bounded_syn_retry_selections(context):
        episode = selection.episode
        if episode is None or len(episode.rows) < 2:
            continue
        duplicates.update(id(flow) for flow in episode.rows[1:] if _pure_packet_level_syn(flow))
    return duplicates


def _pure_packet_level_syn(flow: Flow) -> bool:
    has_payload = bool(
        flow.payload_hash
        or flow.last_payload_hash
        or flow.payload_prefix_hash
        or flow.payload_simhash
        or (flow.payload_length or 0) > 0
    )
    return (
        flow.packet_count == 1
        and flow.tcp_syn_count == 1
        and flow.tcp_syn_only_count == 1
        and flow.tcp_syn_ack_count == 0
        and flow.tcp_ack_count == 0
        and flow.tcp_rst_count == 0
        and not flow.bidirectional
        and not has_payload
    )


def control_filtered_tcp_profiles(
    context: AnalysisContext,
) -> tuple[dict[str, list[FlowRow]], dict[str, dict[TCPConnectionKey, TCPConnectionProfile]]]:
    raw = _without_outbound_control_floods(context, _raw_groups(context))
    duplicates = syn_retry_duplicate_flow_ids(context)
    retained = {
        candidate: [row for row in rows if id(row[1]) not in duplicates]
        for candidate, rows in raw.items()
    }
    return tcp_profiles(context, {candidate: rows for candidate, rows in retained.items() if rows})


def qualified_candidate_groups(context: AnalysisContext) -> dict[str, list[FlowRow]]:
    raw, profiles = control_filtered_tcp_profiles(context)
    if not bool(context.parameters.get("tcp_session_gating_enabled", True)):
        return raw
    allow_legacy = bool(context.parameters.get("tcp_allow_legacy_without_flags", True))
    require_established = bool(context.parameters.get("tcp_require_established_outbound", False))
    grouped: dict[str, list[FlowRow]] = {}
    for candidate, rows in raw.items():
        connections = profiles.get(candidate, {})
        suppressed = scan_suppressed_keys(context, connections)
        selected: list[FlowRow] = []
        for row in rows:
            flow = row[1]
            if flow.protocol.upper() != "TCP":
                selected.append(row)
                continue
            key = _connection_key(context, flow)
            profile = connections.get(key) if key is not None else None
            if key in suppressed:
                continue
            if (
                require_established
                and profile is not None
                and profile.metadata_available
                and profile.outbound_syn_unanswered
            ):
                # Outbound SYN without a SYN-ACK or ACK: the connection never
                # completed, so this row contributes no session evidence.
                continue
            if profile is None:
                if allow_legacy and not flow.tcp_flags_observed:
                    selected.append(row)
            elif profile.metadata_available:
                if profile.qualified:
                    selected.append(row)
            elif allow_legacy:
                selected.append(row)
        if selected:
            grouped[candidate] = selected
    return grouped


def qualified_tcp_flow_ids(context: AnalysisContext) -> set[int]:
    raw, profiles = control_filtered_tcp_profiles(context)
    if not bool(context.parameters.get("tcp_session_gating_enabled", True)):
        return {
            id(flow)
            for rows in raw.values()
            for _host, flow in rows
            if flow.protocol.upper() == "TCP"
        }
    allow_legacy = bool(context.parameters.get("tcp_allow_legacy_without_flags", True))
    require_established = bool(context.parameters.get("tcp_require_established_outbound", False))
    qualified: set[int] = set()
    for candidate, rows in raw.items():
        connections = profiles.get(candidate, {})
        suppressed = scan_suppressed_keys(context, connections)
        for row in rows:
            flow = row[1]
            if flow.protocol.upper() != "TCP":
                continue
            key = _connection_key(context, flow)
            if key in suppressed:
                continue
            profile = connections.get(key) if key is not None else None
            if (
                require_established
                and profile is not None
                and profile.metadata_available
                and profile.outbound_syn_unanswered
            ):
                continue
            if profile is None:
                if allow_legacy and not flow.tcp_flags_observed:
                    qualified.add(id(flow))
            elif (profile.metadata_available and profile.qualified) or (
                not profile.metadata_available and allow_legacy
            ):
                qualified.add(id(flow))
    return qualified
