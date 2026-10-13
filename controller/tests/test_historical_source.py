"""Actual stored values -> immutable source -> real all-stream producer."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b
from c2hunter_analysis.domain import Flow

from c2hunter_controller import historical_baseline as h

START = datetime(2026, 1, 1, tzinfo=UTC)
RECEIPT = "12345678-1234-1234-1234-123456789abc"


def config() -> h.ScopeConfig:
    return h.ScopeConfig.from_mapping(
        {
            "scope_id": RECEIPT,
            "name": "fixture",
            "kind": "OPERATIONAL",
            "sensor_key": "logical",
            "stored_sensor_id": "sensor",
            "internal_networks": ["10.0.0.0/24"],
            "window_seconds": 60,
            "hosts": [{"ip": "10.0.0.1", "epoch": "one"}, {"ip": "10.0.0.2", "epoch": "two"}],
            "identity_assertion": "STABLE_SINGLE_HOST_NO_SHARED_NAT",
            "reason": "fixture",
        }
    )


def review() -> h.QualityReview:
    return h.QualityReview(
        representative_window_asserted=True,
        stable_host_attribution_asserted=True,
        clock_offset_bound_ms=100,
        sensor_alias_asserted=False,
        note="fixture",
    )


def stored(*, aggregate: bool = False) -> dict[str, Any]:
    rows = []
    for host in ("10.0.0.1", "10.0.0.2"):
        for port in (443, 8443):
            for index in range(8):
                rows.append(
                    {
                        "sensor_id": "sensor",
                        "timestamp": (START + timedelta(seconds=index)).isoformat(),
                        "source_ip": host,
                        "destination_ip": "203.0.113.9",
                        "source_port": 40000,
                        "destination_port": port,
                        "protocol": "TCP",
                        "direction": "OUTBOUND",
                        "packet_count": 2 if aggregate else 1,
                        "total_bytes": 100 + index,
                        "duration_seconds": 0.25 if aggregate else 0,
                    }
                )
    return {
        "id": "root",
        "dataset_id": "dataset",
        "parent_job_id": None,
        "source_type": "SENSOR_CAPTURE",
        "mode": "LIVE",
        "status": "COMPLETED",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(seconds=60)).isoformat(),
        "sensor_ids": ["sensor"],
        "internal_networks": ["10.0.0.0/24"],
        "analysis": {"module": "c2"},
        "allowlist": [],
        "flow_records": rows,
    }


def project(raw: dict[str, Any]) -> Any:
    from c2hunter_controller.historical_source import project_source

    return project_source(raw, ancestors=(), scope=config(), quality_review=review())


def test_missing_raw_duration_rejects_before_real_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = stored()
    del raw["flow_records"][-1]["duration_seconds"]
    calls = []
    monkeypatch.setattr(b, "build_behavior_windows", lambda request: calls.append(request))
    with pytest.raises(ValueError):
        project(raw)
    assert calls == []


class TestStrictSource:
    @pytest.mark.parametrize(
        "field",
        [
            "timestamp",
            "packet_count",
            "total_bytes",
            "duration_seconds",
            "sensor_id",
            "source_ip",
            "destination_ip",
            "protocol",
            "direction",
        ],
    )
    def test_required_presence(self, field: str) -> None:
        raw = stored()
        del raw["flow_records"][-1][field]
        with pytest.raises(ValueError):
            project(raw)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("duration_seconds", 0.0000001),
            ("duration_seconds", 61),
            ("duration_seconds", True),
            ("packet_count", True),
            ("packet_count", 0),
            ("total_bytes", "1"),
            ("timestamp", "2026-01-01T00:00:00"),
            ("tcp_flags_observed", 1),
            ("bidirectional", 0),
            ("tcp_syn_count", -1),
            ("tcp_flags", {"syn": -1}),
            ("sensor_id", "other"),
            ("direction", "INBOUND"),
        ],
    )
    def test_malformed_row_rejected(self, field: str, value: Any) -> None:
        raw = stored()
        raw["flow_records"][-1][field] = value
        with pytest.raises(ValueError):
            project(raw)

    @pytest.mark.parametrize(
        "mutation", ["networks", "duration", "internal_host", "both_internal_host", "origin"]
    )
    def test_scope_enforced_before_builder(
        self, mutation: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = stored()
        if mutation == "networks":
            raw["internal_networks"] = ["10.0.0.0/16"]
        elif mutation == "duration":
            raw["end_time"] = (START + timedelta(seconds=61)).isoformat()
        elif mutation == "internal_host":
            raw["flow_records"][0]["source_ip"] = "10.0.0.3"
        elif mutation == "both_internal_host":
            raw["flow_records"][0]["destination_ip"] = "10.0.0.3"
        else:
            digest = "a" * 64
            raw.update(
                source_type="PCAP_UPLOAD",
                mode="PCAP_UPLOAD",
                dataset_id="pcap:" + digest,
                source={"sha256": digest},
            )
        calls = []
        monkeypatch.setattr(b, "build_behavior_windows", lambda request: calls.append(request))
        with pytest.raises(ValueError):
            project(raw)
        assert calls == []

    def test_unknown_missing_port_and_excluded_rows(self) -> None:
        from c2hunter_controller.historical_source import source_build_input

        raw = stored()
        raw["flow_records"][0]["direction"] = "unknown"
        raw["flow_records"][1].pop("destination_port")
        raw["flow_records"].extend(
            [
                dict(raw["flow_records"][2], destination_ip="10.0.0.2", direction="UNKNOWN"),
                dict(raw["flow_records"][2], source_ip="198.51.100.1", direction="UNKNOWN"),
            ]
        )
        source = project(raw)
        assert source.strict_flows[1].destination_port is None
        result = b.build_behavior_windows(
            source_build_input(
                source, scope=config(), quality_review=review(), source_receipt_id=None
            )
        )
        assert result.excluded_row_count == 2
        assert "DERIVED_FROM_CIDR" in result.limitations
        assert "SERVICE_PORT_UNAVAILABLE" in result.limitations

    def test_alias_explicit_and_missing_review_not_invented(self) -> None:
        from c2hunter_controller.historical_source import (
            project_source,
            source_build_input,
            target_vetoes,
        )

        scope = h.ScopeConfig.from_mapping(
            dict(config().to_mapping(), kind="EVALUATION", stored_sensor_id=None)
        )
        raw = stored()
        with pytest.raises(ValueError):
            project_source(raw, ancestors=(), scope=scope, quality_review=None)
        alias = h.QualityReview.from_mapping(
            dict(review().to_mapping(), sensor_alias_asserted=True)
        )
        source = project_source(raw, ancestors=(), scope=scope, quality_review=alias)
        request = source_build_input(
            source, scope=scope, quality_review=alias, source_receipt_id=None
        )
        assert request.actual_sensor_id == "sensor"
        assert request.sensor_alias_asserted is True
        assert target_vetoes(source, quality_review=None) == ("TARGET_REVIEW_REQUIRED",)
        assert target_vetoes(source, quality_review=alias) == ()
        assert source.quality.producer_completeness == "UNKNOWN"

    def test_exact_tail_boundary(self) -> None:
        raw = stored()
        raw["flow_records"][0].update(
            timestamp=(START + timedelta(seconds=59, microseconds=999999)).isoformat(),
            duration_seconds=0.000001,
        )
        assert project(raw).strict_flows[0].duration_seconds == 0.000001
        raw["flow_records"][0]["duration_seconds"] = 0.000002
        with pytest.raises(ValueError):
            project(raw)


class TestSavedTrust:
    @pytest.mark.parametrize("kind,value", [("IP", "203.0.113.9"), ("CIDR", "203.0.113.99/24")])
    @pytest.mark.parametrize(
        "expiry,enabled,trusted",
        [
            (None, True, True),
            ("2026-01-01T00:01:00.000001Z", True, True),
            ("2026-01-01T00:01:00Z", True, False),
            ("2025-12-31T23:59:59Z", True, False),
            (None, False, False),
        ],
    )
    def test_saved_snapshot_at_declared_end(
        self, kind: str, value: str, expiry: str | None, enabled: bool, trusted: bool
    ) -> None:
        from c2hunter_controller.historical_source import source_build_input

        raw = stored()
        raw["allowlist"] = [
            {
                "type": kind,
                "value": value,
                "description": "saved",
                "enabled": enabled,
                "expires_at": expiry,
            }
        ]
        source = project(raw)
        assert source.trusted_peers == (("203.0.113.9",) if trusted else ())
        result = b.build_behavior_windows(
            source_build_input(
                source, scope=config(), quality_review=review(), source_receipt_id=None
            )
        )
        assert result.eligible_profile_count == (0 if trusted else 4)
        assert h.thaw_original_job(source.original)["allowlist"] == raw["allowlist"]

    @pytest.mark.parametrize("kind", ["DOMAIN_SUFFIX", "TLS_FINGERPRINT", "CERT_FINGERPRINT"])
    def test_non_ip_not_trust(self, kind: str) -> None:
        raw = stored()
        raw["allowlist"] = [
            {"type": kind, "value": "example.test", "description": "saved", "enabled": True}
        ]
        assert project(raw).trusted_peers == ()

    @pytest.mark.parametrize(
        "changed",
        [
            {"enabled": 1},
            {"enabled": None},
            {"expires_at": "bad"},
            {"expires_at": "2026-01-01"},
            {"value": "bad"},
            {"type": "CIDR", "value": "bad"},
        ],
    )
    def test_malformed_saved_entries_reject(self, changed: dict[str, Any]) -> None:
        raw = stored()
        raw["allowlist"] = [
            dict(
                {"type": "IP", "value": "203.0.113.9", "description": "saved", "enabled": True},
                **changed,
            )
        ]
        with pytest.raises(ValueError):
            project(raw)

    def test_raw_allowlist_cap_before_dedupe(self) -> None:
        raw = stored()
        entry = {"type": "IP", "value": "203.0.113.9", "description": "saved"}
        raw["allowlist"] = [entry] * 128
        assert project(raw).trusted_peers == ("203.0.113.9",)
        raw["allowlist"].append(entry)
        with pytest.raises(ValueError):
            project(raw)


class TestObservationIdentity:
    def test_multiset_root_and_local_binding_are_distinct(self) -> None:
        from copy import deepcopy

        raw = stored()
        source = project(raw)
        assert len(source.observation_sha256) == len(source.feature_observation_sha256) == 64
        reordered = deepcopy(raw)
        reordered["flow_records"].reverse()
        other = project(reordered)
        assert other.observation_sha256 == source.observation_sha256
        assert other.feature_observation_sha256 == source.feature_observation_sha256
        assert h.source_binding_sha256(
            other.source_binding(), purpose="APPROVAL"
        ) != h.source_binding_sha256(source.source_binding(), purpose="APPROVAL")
        changed_root = deepcopy(raw)
        changed_root.update(id="another", dataset_id="another-dataset")
        other = project(changed_root)
        assert other.observation_sha256 != source.observation_sha256
        assert other.feature_observation_sha256 == source.feature_observation_sha256
        duplicate = deepcopy(raw)
        duplicate["flow_records"].append(duplicate["flow_records"][0])
        assert project(duplicate).feature_observation_sha256 != source.feature_observation_sha256

    def test_reanalysis_same_root_and_irrelevant_metadata(self) -> None:
        from c2hunter_controller.historical_source import project_source

        raw = stored()
        source = project(raw)
        child = dict(raw, id="child", parent_job_id="root")
        projected = project_source(
            child,
            ancestors=({k: v for k, v in raw.items() if k != "flow_records"},),
            scope=config(),
            quality_review=review(),
        )
        assert projected.observation_sha256 == source.observation_sha256
        raw["analysis"]["beacon_interval_tolerance"] = 0.25
        raw["flow_records"][0]["Raw_Payload"] = "secret"
        raw["flow_records"][0]["score"] = 100
        assert project(raw).feature_observation_sha256 == source.feature_observation_sha256

    @pytest.mark.parametrize(
        "field,value",
        [
            ("source_port", 40001),
            ("destination_port", 444),
            ("protocol", "UDP"),
            ("packet_count", 2),
            ("total_bytes", 999),
            ("duration_seconds", 0.1),
            ("tcp_flags", {"syn": 1}),
            ("tcp_flags_observed", True),
            ("tcp_syn_count", 1),
            ("tcp_ack_count", 1),
            ("tcp_rst_count", 1),
            ("tcp_syn_only_count", 1),
            ("tcp_syn_ack_count", 1),
            ("tcp_ack_only_count", 1),
            ("tcp_syn_only_observations", [[0, 99]]),
            ("tcp_syn_only_observations_truncated", True),
            ("bidirectional", True),
            ("payload_length", 1),
            ("payload_hash", "digest"),
            ("last_payload_hash", "digest"),
            ("payload_prefix_hash", "digest"),
            ("payload_simhash", "digest"),
        ],
    )
    def test_consumed_observation_changes_digest(self, field: str, value: Any) -> None:
        raw = stored()
        before = project(raw).feature_observation_sha256
        raw["flow_records"][0][field] = value
        assert project(raw).feature_observation_sha256 != before

    def test_payload_identity_omitted_but_suppression_presence_retained(self) -> None:
        raw = stored()
        raw["flow_records"][0]["payload_hash"] = "first-hash"
        source = project(raw)
        raw["flow_records"][0]["payload_hash"] = "second-hash"
        assert project(raw).feature_observation_sha256 == source.feature_observation_sha256
        raw["flow_records"][0]["payload_hash"] = None
        assert project(raw).feature_observation_sha256 != source.feature_observation_sha256

    def test_equivalent_time_cidr_protocol_and_numeric_encoding(self) -> None:
        raw = stored()
        source = project(raw)
        raw["start_time"] = "2026-01-01T09:00:00+09:00"
        raw["end_time"] = "2026-01-01T09:01:00+09:00"
        raw["internal_networks"] = ["10.0.0.123/24"]
        raw["flow_records"][0].update(
            timestamp="2026-01-01T09:00:00+09:00", protocol="tcp", duration_seconds=0.0
        )
        assert project(raw).observation_sha256 == source.observation_sha256

    def test_saved_trust_affects_hash(self) -> None:
        raw = stored()
        before = project(raw).feature_observation_sha256
        raw["allowlist"] = [
            {"type": "IP", "value": "203.0.113.9", "description": "saved", "enabled": True}
        ]
        assert project(raw).feature_observation_sha256 != before

    def test_alias_content_uses_logical_sensor_not_actual(self) -> None:
        from c2hunter_controller.historical_source import project_source

        scope = h.ScopeConfig.from_mapping(
            dict(config().to_mapping(), kind="EVALUATION", stored_sensor_id=None)
        )
        alias = h.QualityReview.from_mapping(
            dict(review().to_mapping(), sensor_alias_asserted=True)
        )
        raw = stored()
        first = project_source(raw, ancestors=(), scope=scope, quality_review=alias)
        raw["sensor_ids"] = ["different"]
        for row in raw["flow_records"]:
            row["sensor_id"] = "different"
        second = project_source(raw, ancestors=(), scope=scope, quality_review=alias)
        assert first.actual_sensor_id != second.actual_sensor_id
        assert first.observation_sha256 == second.observation_sha256
        assert first.feature_observation_sha256 == second.feature_observation_sha256


class TestImmutableAdmission:
    def test_original_and_nested_flow_cannot_be_mutated(self) -> None:
        from dataclasses import FrozenInstanceError

        raw = stored()
        raw["flow_records"][0].update(
            tcp_flags={"ack": 1},
            packet_sizes=[10, 20],
            tcp_syn_only_observations=[[0, 7]],
            Raw_Payload="private",
            payload="private-again",
        )
        source = project(raw)
        row = source.strict_flows[0]
        assert type(row) is Flow
        with pytest.raises(TypeError):
            row.tcp_flags["ack"] = 2
        with pytest.raises(FrozenInstanceError):
            row.packet_count = 9
        before = source.to_mapping()
        raw["flow_records"][0]["tcp_flags"]["ack"] = 99
        raw["flow_records"][0]["packet_sizes"].append(99)
        raw["flow_records"][0]["tcp_syn_only_observations"][0][1] = 99
        assert source.to_mapping() == before
        assert h.projected_payload_fields_excluded(source.original.flow_records) == 1
        assert source.original.flow_records[0].sensitive_keys_present == ("Raw_Payload", "payload")
        assert "private" not in str(before)

    @pytest.mark.parametrize("route", ["constructor", "mapping"])
    @pytest.mark.parametrize(
        "field,value",
        [
            ("packet_count", True),
            ("total_bytes", 999),
            ("packet_sizes", [4]),
            ("source_ip", "10.0.0.2"),
        ],
    )
    def test_derivatives_cannot_disagree_with_original(
        self, route: str, field: str, value: Any
    ) -> None:
        from c2hunter_controller.historical_source import SourceProjection

        source = project(stored())
        mapping = source.to_mapping()
        mapping["strict_flows"][0][field] = value
        with pytest.raises(ValueError):
            SourceProjection(
                **mapping
            ) if route == "constructor" else SourceProjection.from_mapping(mapping)

    @pytest.mark.parametrize("route", ["constructor", "mapping"])
    def test_trust_cannot_be_injected(self, route: str) -> None:
        from c2hunter_controller.historical_source import SourceProjection

        mapping = project(stored()).to_mapping()
        mapping["trusted_peers"] = ["203.0.113.9"]
        with pytest.raises(ValueError):
            SourceProjection(
                **mapping
            ) if route == "constructor" else SourceProjection.from_mapping(mapping)

    def test_closed_full_projection_roundtrip(self) -> None:
        import json

        from c2hunter_controller.historical_source import SourceProjection, source_build_input

        source = project(stored())
        mapping = json.loads(json.dumps(source.to_mapping()))  # preserve original object order
        assert set(mapping) == set(h.SourceBindingProjection.model_fields) | {
            "strict_flows",
            "trusted_peers",
            "observation_sha256",
            "feature_observation_sha256",
        }
        for restored in (
            SourceProjection(**mapping),
            SourceProjection.model_validate(mapping),
            SourceProjection.from_mapping(mapping),
        ):
            assert restored == source
            b.baseline_build_to_mapping(
                b.build_behavior_windows(
                    source_build_input(
                        restored, scope=config(), quality_review=None, source_receipt_id=None
                    )
                )
            )
        for name in mapping:
            with pytest.raises(ValueError):
                SourceProjection.from_mapping({k: v for k, v in mapping.items() if k != name})
        with pytest.raises(ValueError):
            SourceProjection.from_mapping(dict(mapping, unexpected=True))

    @pytest.mark.parametrize(
        "receipt",
        [
            "12345678123412341234123456789abc",
            "12345678-1234-1234-1234-123456789ABC",
            1,
            " " + RECEIPT,
        ],
    )
    def test_receipt_literal_not_repaired(self, receipt: Any) -> None:
        from c2hunter_controller.historical_source import source_build_input

        with pytest.raises(ValueError):
            source_build_input(
                project(stored()),
                scope=config(),
                quality_review=review(),
                source_receipt_id=receipt,
            )

    @pytest.mark.parametrize("mutation", ["syn", "flags", "counter"])
    def test_raw_bounds_before_flow_normalization(
        self, mutation: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from c2hunter_controller import historical_source as s

        raw = stored()
        if mutation == "syn":
            raw["flow_records"][0]["tcp_syn_only_observations"] = [[0, 7]] * 256
            raw["flow_records"][1]["tcp_syn_only_observations"] = [[0, 7]]
        elif mutation == "flags":
            raw["flow_records"][-1]["tcp_flags"] = {str(i): 1 for i in range(17)}
        else:
            raw["flow_records"][-1]["tcp_ack_count"] = 2**53 + 1
        calls = []
        original = s.normalize_tcp_syn_observations

        def spy(value: object) -> Any:
            calls.append(value)
            return original(value)

        monkeypatch.setattr(s, "normalize_tcp_syn_observations", spy)
        with pytest.raises(ValueError):
            project(raw)
        assert calls == []

    def test_safe_errors_have_no_source_values(self) -> None:
        raw = stored()
        raw["flow_records"][0]["source_ip"] = "/private/source/path"
        with pytest.raises(ValueError) as error:
            project(raw)
        assert error.value.code == "BASELINE_SOURCE_INVALID"
        assert "private" not in str(error.value)

    @pytest.mark.parametrize(
        "field,value", [("module", None), ("status", "RUNNING"), ("source_type", "UNKNOWN")]
    )
    def test_no_invented_source_state_or_module(self, field: str, value: Any) -> None:
        raw = stored()
        if field == "module":
            raw["analysis"].pop("module")
        else:
            raw[field] = value
        with pytest.raises(ValueError):
            project(raw)


class TestBoundaryAndConsumers:
    def test_direct_projection_rejects_tail_and_sensor_in_original_too(self) -> None:
        from c2hunter_controller.historical_source import SourceProjection

        for name, value in (
            ("duration_seconds", 61),
            ("sensor_id", "other"),
            ("direction", "INBOUND"),
        ):
            mapping = project(stored()).to_mapping()
            mapping["original"]["flow_records"][0]["fields"][name] = value
            mapping["strict_flows"][0][name] = value
            with pytest.raises(ValueError):
                SourceProjection.from_mapping(mapping)

    def test_projection_caps_before_mutable_strict_copy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from c2hunter_controller import historical_source as s

        mapping = project(stored()).to_mapping()
        mapping["strict_flows"][0]["tcp_syn_only_observations"] = [[0, 1]] * 256
        mapping["strict_flows"][1]["tcp_syn_only_observations"] = [[0, 1]]
        calls = []
        original = s.normalize_tcp_syn_observations

        def spy(value: object) -> Any:
            calls.append(value)
            return original(value)

        monkeypatch.setattr(s, "normalize_tcp_syn_observations", spy)
        with pytest.raises(ValueError):
            s.SourceProjection.from_mapping(mapping)
        assert calls == []

    def test_mixed_flood_retains_ack_udp_payload_inbound(self) -> None:
        from c2hunter_controller.historical_source import source_build_input

        raw = stored()
        base = raw["flow_records"][0]
        flood = dict(
            base,
            packet_count=1000,
            total_bytes=40000,
            duration_seconds=1,
            tcp_flags_observed=True,
            tcp_syn_count=1000,
            tcp_syn_only_count=1000,
            tcp_flags={"syn": 1000},
            destination_port=555,
        )
        raw["flow_records"] = [flood]
        for i in range(8):
            raw["flow_records"].extend(
                [
                    dict(
                        base,
                        timestamp=(START + timedelta(seconds=i)).isoformat(),
                        tcp_flags={"ack": 1},
                        tcp_ack_count=1,
                    ),
                    dict(
                        base,
                        timestamp=(START + timedelta(seconds=i)).isoformat(),
                        protocol="UDP",
                        destination_port=444,
                    ),
                    dict(
                        base,
                        timestamp=(START + timedelta(seconds=i)).isoformat(),
                        payload_hash="present",
                        tcp_flags={"syn": 1},
                        destination_port=445,
                    ),
                ]
            )
        raw["flow_records"].append(
            dict(
                base,
                source_ip="203.0.113.9",
                destination_ip="10.0.0.1",
                source_port=443,
                destination_port=40000,
                direction="INBOUND",
                total_bytes=800,
                payload_length=8,
            )
        )
        source = project(raw)
        result = b.build_behavior_windows(
            source_build_input(
                source, scope=config(), quality_review=review(), source_receipt_id=RECEIPT
            )
        )
        assert result.raw_profile_count == 4
        assert result.eligible_profile_count == 3
        assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in result.limitations
        windows = {p.stream.service_port: p.window for p in result.profiles}
        assert windows[555] is None
        assert all(windows[port].outbound_record_count == 8 for port in (443, 444, 445))
        assert windows[443].outbound_share == 0.5
        raw["flow_records"].reverse()
        permuted = project(raw)
        assert permuted.observation_sha256 == source.observation_sha256
        assert b.baseline_build_to_mapping(
            b.build_behavior_windows(
                source_build_input(
                    permuted, scope=config(), quality_review=review(), source_receipt_id=RECEIPT
                )
            )
        ) == b.baseline_build_to_mapping(result)

    def test_all_quality_negatives_survive_child_to_target_veto(self) -> None:
        from c2hunter_controller.historical_source import project_source, target_vetoes

        raw = stored()
        raw.update(
            capture_incomplete=True,
            source={"skipped_packet_count": 3},
            operations={"sensors": {"sensor": {"clock_offset_ms": -2001}}},
        )
        child = dict(stored(), id="child", parent_job_id="root")
        grandchild = dict(stored(), id="grandchild", parent_job_id="child")
        source = project_source(
            grandchild, ancestors=(raw, child), scope=config(), quality_review=review()
        )
        assert source.quality.skipped_packet_count.value == 3
        assert target_vetoes(source, quality_review=review()) == (
            "SOURCE_CLOCK_UNCERTAIN",
            "TARGET_PARTIAL_CAPTURE",
        )
        assert target_vetoes(source, quality_review=None) == (
            "SOURCE_CLOCK_UNCERTAIN",
            "TARGET_PARTIAL_CAPTURE",
            "TARGET_REVIEW_REQUIRED",
        )

    def test_source_and_target_do_not_share_allowlist(self) -> None:
        raw = stored()
        raw["allowlist"] = [{"type": "IP", "value": "203.0.113.9", "description": "only source"}]
        assert project(raw).trusted_peers == ("203.0.113.9",)
        assert project(stored()).trusted_peers == ()

    def test_real_stored_schema_producer(self) -> None:
        from c2hunter_controller.historical_source import source_build_input
        from c2hunter_controller.jobs import build_job
        from c2hunter_controller.schemas import AnalysisJobCreate

        raw = stored()
        payload = AnalysisJobCreate.model_validate(
            {
                k: raw[k]
                for k in (
                    "mode",
                    "sensor_ids",
                    "start_time",
                    "end_time",
                    "internal_networks",
                    "analysis",
                    "flow_records",
                )
            }
            | {"name": "actual producer", "idempotency_key": "fixture", "capture": {}}
        )
        produced = build_job(payload)
        produced["status"] = "COMPLETED"
        source = project(produced)
        result = b.build_behavior_windows(
            source_build_input(
                source, scope=config(), quality_review=review(), source_receipt_id=None
            )
        )
        assert result.eligible_profile_count == 4

    def test_observation_tuple_exact_schema_and_consumer_payload_projection(self) -> None:
        from c2hunter_controller import historical_source as s

        raw = stored()
        raw["flow_records"][0].update(tcp_flags={"ack": 1.0}, payload_prefix_hash="SECRET_HASH")
        source = project(raw)
        row = s._observation(source.strict_flows[0], "logical")
        assert len(s.OBSERVATION_FIELDS) == len(row) == 23
        mapped = dict(zip(s.OBSERVATION_FIELDS, row, strict=True))
        assert mapped["logical_sensor"] == "logical"
        assert mapped["timestamp_us"] == 1767225600000000
        assert mapped["duration_us"] == 0
        assert mapped["payload_observed"] is True
        assert mapped["tcp_flags"] == (("ack", "1"),)
        assert "SECRET_HASH" not in h.canonical_json(row)


class TestFinalBounds:
    @pytest.mark.parametrize("ancestor", [None, True, [], "not-metadata"])
    def test_invalid_ancestor_has_safe_domain_error(self, ancestor: Any) -> None:
        from c2hunter_controller.historical_source import SourceInputError, project_source

        with pytest.raises(SourceInputError) as error:
            project_source(stored(), ancestors=(ancestor,), scope=config(), quality_review=review())
        assert error.value.code == "BASELINE_SOURCE_INVALID"

    def test_direct_flow_cannot_smuggle_naive_timestamp(self) -> None:
        from dataclasses import replace

        from c2hunter_controller.historical_source import SourceProjection

        source = project(stored())
        values = {name: getattr(source, name) for name in SourceProjection.model_fields}
        values["strict_flows"] = (
            replace(source.strict_flows[0], timestamp=START.replace(tzinfo=None)),
            *source.strict_flows[1:],
        )
        with pytest.raises(ValueError):
            SourceProjection(**values)

    def test_source_receipt_requires_explicit_review(self) -> None:
        from c2hunter_controller.historical_source import source_build_input

        with pytest.raises(ValueError):
            source_build_input(
                project(stored()), scope=config(), quality_review=None, source_receipt_id=RECEIPT
            )

    def test_accepted_binding_to_complete_projection(self) -> None:
        from c2hunter_controller.historical_source import source_from_binding

        source = project(stored())
        assert (
            source_from_binding(source.source_binding(), scope=config(), quality_review=review())
            == source
        )
        assert (
            source_from_binding(source.source_binding(), scope=config(), quality_review=None)
            == source
        )

    def test_raw_row_cap_exact_and_plus_one(self) -> None:
        raw = stored()
        raw["flow_records"] = [raw["flow_records"][0]] * 8192
        assert len(project(raw).strict_flows) == 8192
        raw["flow_records"].append(raw["flow_records"][0])
        with pytest.raises(ValueError):
            project(raw)

    def test_syn_exact_limit_retains_duplicates(self) -> None:
        raw = stored()
        raw["flow_records"][0]["tcp_syn_only_observations"] = [
            {"offset_us": 0, "sequence": 7}
        ] * 256
        source = project(raw)
        assert source.strict_flows[0].tcp_syn_only_observations == ((0, 7),) * 256
        raw["flow_records"][1]["tcp_syn_only_observations"] = [[0, 7]]
        with pytest.raises(ValueError):
            project(raw)

    def test_trusted_peer_cap(self) -> None:
        raw = stored()
        base = raw["flow_records"][0]
        raw["allowlist"] = [{"type": "CIDR", "value": "203.0.113.0/24", "description": "saved"}]
        raw["flow_records"] = [dict(base, destination_ip=f"203.0.113.{i}") for i in range(128)]
        assert len(project(raw).trusted_peers) == 128
        raw["flow_records"].append(dict(base, destination_ip="203.0.113.128"))
        with pytest.raises(ValueError) as error:
            project(raw)
        assert error.value.code == "BASELINE_SOURCE_LIMIT"

    def test_raw_stream_cap_real_producer_before_feature_work(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from c2hunter_controller.historical_source import source_build_input

        raw = stored()
        base = raw["flow_records"][0]
        raw["flow_records"] = [dict(base, destination_port=1000 + i) for i in range(128)]
        source = project(raw)
        result = b.build_behavior_windows(
            source_build_input(source, scope=config(), quality_review=None, source_receipt_id=None)
        )
        assert result.raw_profile_count == 128
        raw["flow_records"].append(dict(base, destination_port=1128))
        source = project(raw)
        calls = []
        monkeypatch.setattr(b, "_dispersion", lambda values: calls.append(values))
        with pytest.raises(b.BaselineInputError) as error:
            b.build_behavior_windows(
                source_build_input(
                    source, scope=config(), quality_review=None, source_receipt_id=None
                )
            )
        assert error.value.code == "BASELINE_PROFILE_LIMIT"
        assert calls == []

    def test_pcap_root_digest_identity_not_submitted_root_name(self) -> None:
        from c2hunter_controller.historical_source import project_source

        raw = stored()
        raw.update(
            source_type="PCAP_UPLOAD",
            mode="PCAP_UPLOAD",
            dataset_id="pcap:" + "a" * 64,
            source={"sha256": "a" * 64},
        )
        scope = h.ScopeConfig.from_mapping(
            dict(config().to_mapping(), kind="EVALUATION", stored_sensor_id=None)
        )
        alias = h.QualityReview.from_mapping(
            dict(review().to_mapping(), sensor_alias_asserted=True)
        )
        first = project_source(raw, ancestors=(), scope=scope, quality_review=alias)
        raw["id"] = "reupload"
        second = project_source(raw, ancestors=(), scope=scope, quality_review=alias)
        assert first.observation_sha256 == second.observation_sha256
        assert first.root_content_sha256 == "a" * 64
        raw.update(dataset_id="pcap:" + "b" * 64, source={"sha256": "b" * 64})
        changed = project_source(raw, ancestors=(), scope=scope, quality_review=alias)
        assert changed.observation_sha256 != first.observation_sha256
        assert changed.feature_observation_sha256 == first.feature_observation_sha256

    def test_hash_tampering_fails_at_scoped_bridge(self) -> None:
        from c2hunter_controller.historical_source import SourceProjection, source_build_input

        for field in ("observation_sha256", "feature_observation_sha256"):
            mapping = project(stored()).to_mapping()
            mapping[field] = "0" * 64
            source = SourceProjection.from_mapping(mapping)
            with pytest.raises(ValueError):
                source_build_input(
                    source, scope=config(), quality_review=None, source_receipt_id=None
                )


@pytest.mark.parametrize("aggregate", [False, True])
def test_actual_producer_roundtrip_all_hosts_and_streams(aggregate: bool) -> None:
    from c2hunter_controller.historical_source import source_build_input

    source = project(stored(aggregate=aggregate))
    request = source_build_input(
        source, scope=config(), quality_review=review(), source_receipt_id=RECEIPT
    )
    result = b.build_behavior_windows(request)
    mapped = b.baseline_build_to_mapping(result)
    assert b.baseline_build_from_mapping(mapped) == result
    assert result.raw_profile_count == result.eligible_profile_count == 4
    assert {p.key.service_port for p in result.profiles if p.key} == {443, 8443}
    assert {p.key.host_epoch for p in result.profiles if p.key} == {"one", "two"}
    for profile in result.profiles:
        assert profile.window is not None
        assert profile.window.source_receipt_id == RECEIPT
        assert profile.window.outbound_record_count == 8
        assert profile.window.size_dispersion is not None
        assert profile.window.outbound_share == 1
        assert (profile.window.recurrence is None) == aggregate
    target = source_build_input(source, scope=config(), quality_review=None, source_receipt_id=None)
    assert all(
        p.window.source_receipt_id is None
        for p in b.build_behavior_windows(target).profiles
        if p.window
    )
