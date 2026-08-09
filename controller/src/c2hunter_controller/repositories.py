from __future__ import annotations

import json
import sqlite3
import threading
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol


class Repository(Protocol):
    """PostgreSQL adapter가 구현해야 하는 제어 영역 경계."""

    def ready(self) -> bool: ...
    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]: ...
    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None: ...
    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None: ...
    def list_sensors(self) -> list[dict[str, Any]]: ...
    def create_group(self, group: dict[str, Any]) -> dict[str, Any]: ...
    def list_groups(self) -> list[dict[str, Any]]: ...
    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...
    def save_job(self, job: dict[str, Any]) -> dict[str, Any]: ...
    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]: ...
    def get_job(self, job_id: str) -> dict[str, Any] | None: ...
    def get_job_summary(self, job_id: str) -> dict[str, Any] | None: ...
    def list_jobs(self) -> list[dict[str, Any]]: ...
    def list_active_live_jobs(self) -> list[dict[str, Any]]: ...
    def delete_job(self, job_id: str) -> bool: ...
    def save_job_capture(self, job_id: str, content: bytes) -> None: ...
    def get_job_capture(self, job_id: str) -> bytes | None: ...
    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None: ...
    def get_candidates(self, job_id: str) -> list[dict[str, Any]]: ...
    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]: ...
    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...
    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_run(self, run_id: str) -> dict[str, Any] | None: ...
    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]: ...
    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None: ...
    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]: ...
    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None: ...
    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]: ...
    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]: ...
    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]: ...
    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None: ...
    def update_candidate(
        self, candidate_id: str, updates: dict[str, Any]
    ) -> dict[str, Any] | None: ...
    def delete_candidate(self, candidate_id: str) -> bool: ...
    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]: ...
    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]: ...
    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]: ...
    def list_candidate_ti_lookups(
        self, candidate_id: str | None = None
    ) -> list[dict[str, Any]]: ...
    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]: ...
    def list_candidate_misp_actions(
        self, candidate_id: str | None = None
    ) -> list[dict[str, Any]]: ...
    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]: ...
    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]: ...
    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]: ...
    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None: ...
    def list_payload_signatures(self) -> list[dict[str, Any]]: ...
    def delete_payload_signature(self, signature_id: str) -> bool: ...
    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]: ...
    def list_allowlist(self) -> list[dict[str, Any]]: ...
    def delete_allowlist(self, entry_id: str) -> bool: ...
    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]: ...
    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None: ...
    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None: ...
    def list_detector_weight_presets(self) -> list[dict[str, Any]]: ...
    def delete_detector_weight_preset(self, preset_id: str) -> bool: ...
    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None: ...
    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]: ...
    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None: ...
    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]: ...
    def save_sensor_pcap_limited(
        self, segment: dict[str, Any], content: bytes, max_total_bytes: int | None
    ) -> tuple[dict[str, Any] | None, str]: ...
    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None: ...
    def list_sensor_pcaps(self) -> list[dict[str, Any]]: ...
    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]: ...
    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None: ...
    def list_enrollments(self) -> list[dict[str, Any]]: ...
    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]: ...
    def claim_enrollment(
        self, token_hash: str, now: datetime
    ) -> tuple[dict[str, Any] | None, str]: ...
    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]: ...
    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None: ...
    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]: ...


class MemoryRepository:
    def __init__(self) -> None:
        self.sensors: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.idempotency_keys: dict[str, str] = {}
        self.candidates: dict[str, list[dict[str, Any]]] = {}
        self.ai_runs: dict[str, dict[str, Any]] = {}
        self.ai_run_idempotency_keys: dict[tuple[str, str], str] = {}
        self.ai_assessments: dict[str, dict[str, Any]] = {}
        self.ai_artifacts: dict[str, dict[str, Any]] = {}
        self.ai_feedback: dict[str, dict[str, Any]] = {}
        self.audit_events: list[dict[str, Any]] = []
        self.candidate_decisions: dict[str, dict[str, Any]] = {}
        self.candidate_ti_lookups: dict[str, dict[str, Any]] = {}
        self.candidate_misp_actions: dict[str, dict[str, Any]] = {}
        self.job_captures: dict[str, bytes] = {}
        self.flow_labels: dict[str, dict[str, Any]] = {}
        self.payload_signatures: dict[str, dict[str, Any]] = {}
        self.allowlist: dict[str, dict[str, Any]] = {}
        self.detector_weight_presets: dict[str, dict[str, Any]] = {}
        self.exports: dict[str, dict[str, Any]] = {}
        self.export_content: dict[str, bytes] = {}
        self.sensor_pcaps: dict[str, dict[str, Any]] = {}
        self.sensor_pcap_content: dict[str, bytes] = {}
        self.enrollments: dict[str, dict[str, Any]] = {}
        self.sensor_credentials: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def ready(self) -> bool:
        return True

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.sensors[sensor["sensor_id"]] = deepcopy(sensor)
            return deepcopy(sensor)

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        value = self.sensors.get(sensor_id)
        return deepcopy(value) if value else None

    def list_sensors(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.sensors.values()))

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.groups[group["id"]] = deepcopy(group)
            return deepcopy(group)

    def list_groups(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.groups.values()))

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            existing_id = self.idempotency_keys.get(job["idempotency_key"])
            if existing_id:
                return deepcopy(self.jobs[existing_id]), False
            self.jobs[job["id"]] = deepcopy(job)
            self.idempotency_keys[job["idempotency_key"]] = job["id"]
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            stored = deepcopy(job)
            existing = self.jobs.get(job["id"])
            if "flow_records" not in stored and existing is not None:
                stored["flow_records"] = deepcopy(existing.get("flow_records", []))
            if "payload_signatures" not in stored and existing is not None:
                stored["payload_signatures"] = deepcopy(existing.get("payload_signatures", []))
            self.jobs[job["id"]] = stored
            return deepcopy(job)

    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]:
        summary = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        return self.save_job(summary)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        value = self.jobs.get(job_id)
        return deepcopy(value) if value else None

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        value = self.jobs.get(job_id)
        if value is None:
            return None
        return deepcopy(
            {
                key: item
                for key, item in value.items()
                if key not in {"flow_records", "payload_signatures"}
            }
        )

    def list_jobs(self) -> list[dict[str, Any]]:
        return [
            deepcopy(
                {
                    key: item
                    for key, item in job.items()
                    if key not in {"flow_records", "payload_signatures"}
                }
            )
            for job in self.jobs.values()
        ]

    def list_active_live_jobs(self) -> list[dict[str, Any]]:
        return [
            deepcopy(
                {
                    key: item
                    for key, item in job.items()
                    if key not in {"flow_records", "payload_signatures"}
                }
            )
            for job in self.jobs.values()
            if job.get("mode") == "LIVE" and job.get("status") in {"CAPTURING", "UPLOADING"}
        ]

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            job = self.jobs.pop(job_id, None)
            if job is None:
                return False
            self.idempotency_keys.pop(str(job["idempotency_key"]), None)
            self.candidates.pop(job_id, None)
            self.job_captures.pop(job_id, None)
            export_ids = [
                export_id
                for export_id, metadata in self.exports.items()
                if metadata.get("job_id") == job_id
            ]
            for export_id in export_ids:
                self.exports.pop(export_id, None)
                self.export_content.pop(export_id, None)
            return True

    def save_job_capture(self, job_id: str, content: bytes) -> None:
        with self._lock:
            self.job_captures[job_id] = bytes(content)

    def get_job_capture(self, job_id: str) -> bytes | None:
        content = self.job_captures.get(job_id)
        return bytes(content) if content is not None else None

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock:
            self.candidates[job_id] = deepcopy(candidates)

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        return deepcopy(self.candidates.get(job_id, []))

    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        key = (run["analysis_job_id"], run["idempotency_key"])
        with self._lock:
            existing_id = self.ai_run_idempotency_keys.get(key)
            if existing_id is not None:
                return deepcopy(self.ai_runs[existing_id]), False
            self.ai_runs[run["id"]] = deepcopy(run)
            self.ai_run_idempotency_keys[key] = run["id"]
            return deepcopy(run), True

    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            existing = self.ai_runs.get(run["id"])
            if existing is not None and existing.get("status") in {
                "COMPLETED",
                "FAILED",
                "CANCELLED",
            }:
                return deepcopy(existing)
            self.ai_runs[run["id"]] = deepcopy(run)
            return deepcopy(run)

    def get_ai_run(self, run_id: str) -> dict[str, Any] | None:
        value = self.ai_runs.get(run_id)
        return deepcopy(value) if value is not None else None

    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (run for run in self.ai_runs.values() if run["analysis_job_id"] == job_id),
                key=lambda run: run["created_at"],
                reverse=True,
            )
        )

    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ai_assessments.setdefault(assessment["id"], deepcopy(assessment))
            return deepcopy(self.ai_assessments[assessment["id"]])

    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        value = self.ai_assessments.get(assessment_id)
        return deepcopy(value) if value is not None else None

    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    assessment
                    for assessment in self.ai_assessments.values()
                    if assessment["ai_run_id"] == run_id
                ),
                key=lambda assessment: assessment["created_at"],
            )
        )

    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ai_artifacts[artifact["id"]] = deepcopy(artifact)
            return deepcopy(artifact)

    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        value = self.ai_artifacts.get(artifact_id)
        return deepcopy(value) if value is not None else None

    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    artifact
                    for artifact in self.ai_artifacts.values()
                    if artifact["assessment_id"] == assessment_id
                ),
                key=lambda artifact: (artifact["created_at"], artifact["artifact_type"]),
            )
        )

    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ai_feedback.setdefault(feedback["id"], deepcopy(feedback))
            return deepcopy(self.ai_feedback[feedback["id"]])

    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    feedback
                    for feedback in self.ai_feedback.values()
                    if feedback["assessment_id"] == assessment_id
                ),
                key=lambda feedback: feedback["created_at"],
            )
        )

    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.audit_events.append(
                {
                    "kind": kind,
                    "object_id": object_id,
                    "occurred_at": datetime.now().astimezone().isoformat(),
                    "data": deepcopy(data),
                }
            )

    def update_candidate(self, candidate_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a candidate and return it, or None if not found."""
        with self._lock:
            for job_id, candidates in self.candidates.items():
                for i, candidate in enumerate(candidates):
                    if candidate.get("id") == candidate_id:
                        # Create updated candidate
                        updated = deepcopy(candidate)
                        updates_copy = deepcopy(updates)

                        if "score_adjustment" in updates_copy:
                            old_score = updated.get("score", 0)
                            adj = updates_copy.pop("score_adjustment")
                            updated["score"] = max(0, min(100, old_score + adj))

                        if "exclude_reason" in updates_copy:
                            updated["excluded"] = True
                            updated["exclude_reason"] = updates_copy.pop("exclude_reason")

                        # Apply any other direct field updates
                        for key, value in updates_copy.items():
                            if isinstance(updated.get(key), list) and isinstance(value, list):
                                updated[key] = value
                            elif isinstance(updated.get(key), dict) and isinstance(value, dict):
                                updated[key].update(value)
                            else:
                                updated[key] = deepcopy(value)

                        # Update timestamp
                        from datetime import UTC

                        updated["updated_at"] = datetime.now(UTC).isoformat()

                        self.candidates[job_id][i] = updated
                        return deepcopy(updated)
        return None

    def delete_candidate(self, candidate_id: str) -> bool:
        """Delete a candidate by ID. Returns True if deleted."""
        with self._lock:
            for job_id, candidates in list(self.candidates.items()):
                original_len = len(candidates)
                self.candidates[job_id] = [c for c in candidates if c.get("id") != candidate_id]
                if len(self.candidates[job_id]) < original_len:
                    return True
            return False

    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]:
        return deepcopy(self.candidates)

    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_decisions[decision["id"]] = deepcopy(decision)
            return deepcopy(decision)

    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self.candidate_decisions.values()
        selected = [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]
        return sorted(deepcopy(selected), key=lambda item: str(item["created_at"]))

    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_ti_lookups[lookup["id"]] = deepcopy(lookup)
            return deepcopy(lookup)

    def list_candidate_ti_lookups(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self.candidate_ti_lookups.values()
        selected = [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]
        return sorted(deepcopy(selected), key=lambda item: str(item["fetched_at"]))

    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_misp_actions[action["id"]] = deepcopy(action)
            return deepcopy(action)

    def list_candidate_misp_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self.candidate_misp_actions.values()
        selected = [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]
        return sorted(deepcopy(selected), key=lambda item: str(item["created_at"]))

    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.flow_labels[label["id"]] = deepcopy(label)
            return deepcopy(label)

    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]:
        labels = list(self.flow_labels.values())
        if job_id is not None:
            labels = [label for label in labels if label.get("job_id") == job_id]
        return sorted(deepcopy(labels), key=lambda item: str(item["created_at"]))

    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.payload_signatures[signature["id"]] = deepcopy(signature)
            return deepcopy(signature)

    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None:
        value = self.payload_signatures.get(signature_id)
        return deepcopy(value) if value else None

    def list_payload_signatures(self) -> list[dict[str, Any]]:
        return sorted(
            deepcopy(list(self.payload_signatures.values())),
            key=lambda item: str(item["created_at"]),
        )

    def delete_payload_signature(self, signature_id: str) -> bool:
        with self._lock:
            return self.payload_signatures.pop(signature_id, None) is not None

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.allowlist[entry["id"]] = deepcopy(entry)
            return deepcopy(entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.allowlist.values()))

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock:
            return self.allowlist.pop(entry_id, None) is not None

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]:
        with self._lock:
            self.exports[export["id"]] = deepcopy(export)
            self.export_content[export["id"]] = bytes(content)
            return deepcopy(export)

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        if export_id not in self.exports:
            return None
        return deepcopy(self.exports[export_id]), bytes(self.export_content[export_id])

    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]:
        stored, status = self.save_sensor_pcap_limited(segment, content, None)
        if stored is None or status not in {"OK", "EXISTS"}:
            raise RuntimeError(f"sensor PCAP save failed: {status}")
        return stored

    def save_sensor_pcap_limited(
        self, segment: dict[str, Any], content: bytes, max_total_bytes: int | None
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            existing = self.sensor_pcaps.get(segment["id"])
            if existing is not None:
                matches = all(
                    existing.get(field) == segment.get(field)
                    for field in ("sensor_id", "analysis_job_id", "sha256")
                )
                return (deepcopy(existing), "EXISTS") if matches else (None, "CONFLICT")
            analysis_job_id = segment.get("analysis_job_id")
            if max_total_bytes is not None and analysis_job_id is not None:
                used = sum(
                    int(item.get("size_bytes", 0) or 0)
                    for item in self.sensor_pcaps.values()
                    if item.get("analysis_job_id") == analysis_job_id
                )
                if used + len(content) > max_total_bytes:
                    return None, "LIMIT"
            self.sensor_pcaps[segment["id"]] = deepcopy(segment)
            self.sensor_pcap_content[segment["id"]] = bytes(content)
            return deepcopy(segment), "OK"

    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None:
        if segment_id not in self.sensor_pcaps:
            return None
        return deepcopy(self.sensor_pcaps[segment_id]), bytes(self.sensor_pcap_content[segment_id])

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.sensor_pcaps.values()))

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.enrollments[enrollment["enrollment_id"]] = deepcopy(enrollment)
            return deepcopy(enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        value = self.enrollments.get(enrollment_id)
        return deepcopy(value) if value else None

    def list_enrollments(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.enrollments.values()))

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            enrollment = next(
                (item for item in self.enrollments.values() if item["token_hash"] == token_hash),
                None,
            )
            if enrollment is None:
                return None, "NOT_FOUND"
            if enrollment.get("revoked_at") is not None:
                return deepcopy(enrollment), "REVOKED"
            if enrollment.get("claimed_at") is not None:
                return deepcopy(enrollment), "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                return deepcopy(enrollment), "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            return deepcopy(enrollment), "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.sensor_credentials[credential["sensor_id"]] = deepcopy(credential)
            return deepcopy(credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        value = self.sensor_credentials.get(sensor_id)
        return deepcopy(value) if value else None

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            sensor = self.sensors.get(sensor_id)
            if sensor is None:
                return None, "NOT_FOUND"
            if sensor.get("config_version") != expected_version:
                return deepcopy(sensor), "CONFLICT"
            sensor.update(deepcopy(configuration))
            sensor["config_version"] = expected_version + 1
            return deepcopy(sensor), "OK"

    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None:
        with self._lock:
            sensor = self.sensors.get(sensor_id)
            if sensor is None:
                return None
            sensor.update(deepcopy(fields))
            return deepcopy(sensor)

    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if preset.get("is_default"):
                for item in self.detector_weight_presets.values():
                    item["is_default"] = False
            self.detector_weight_presets[preset["id"]] = deepcopy(preset)
            return deepcopy(preset)

    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        with self._lock:
            preset = self.detector_weight_presets.get(preset_id)
            return deepcopy(preset) if preset is not None else None

    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None:
        with self._lock:
            preset = self.detector_weight_presets.get(preset_id)
            if preset is None:
                return None
            preset.update(deepcopy(updates))
            if set_as_default:
                for item in self.detector_weight_presets.values():
                    item["is_default"] = item["id"] == preset_id
            return deepcopy(preset)

    def list_detector_weight_presets(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(list(self.detector_weight_presets.values()))

    def delete_detector_weight_preset(self, preset_id: str) -> bool:
        with self._lock:
            return self.detector_weight_presets.pop(preset_id, None) is not None

    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        with self._lock:
            selected = self.detector_weight_presets.get(preset_id)
            if selected is None:
                return None
            for preset in self.detector_weight_presets.values():
                preset["is_default"] = preset["id"] == preset_id
            return deepcopy(selected)


class SQLiteRepository:
    """외부 서비스 없이 계약 테스트 가능한 SQLite adapter. 같은 경계로 PostgreSQL 교체 가능."""

    def __init__(self, path: str | Path) -> None:
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.RLock()
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS objects (
              kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
              PRIMARY KEY(kind, id)
            );
            CREATE TABLE IF NOT EXISTS idempotency (
              key TEXT PRIMARY KEY, job_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidates (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_analysis_runs (
              run_id TEXT PRIMARY KEY,
              analysis_job_id TEXT NOT NULL,
              idempotency_key TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL,
              UNIQUE(analysis_job_id, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS ai_analysis_runs_job_created
              ON ai_analysis_runs(analysis_job_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS ai_candidate_assessments (
              assessment_id TEXT PRIMARY KEY,
              ai_run_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ai_candidate_assessments_run_created
              ON ai_candidate_assessments(ai_run_id, created_at);
            CREATE TABLE IF NOT EXISTS ai_generated_artifacts (
              artifact_id TEXT PRIMARY KEY,
              assessment_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ai_generated_artifacts_assessment_created
              ON ai_generated_artifacts(assessment_id, created_at);
            CREATE TABLE IF NOT EXISTS ai_feedback (
              feedback_id TEXT PRIMARY KEY,
              assessment_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ai_feedback_assessment_created
              ON ai_feedback(assessment_id, created_at);
            CREATE TABLE IF NOT EXISTS audit_events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL,
              object_id TEXT NOT NULL,
              occurred_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_flow_records (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_payload_signatures (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_capture_blobs (
              job_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS export_blobs (
              export_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sensor_pcap_blobs (
              segment_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
        """)
        self._migrate_embedded_job_flows()
        self._migrate_embedded_job_signatures()
        self.connection.commit()

    @staticmethod
    def _serialize(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), default=str)

    def _put(self, kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT INTO objects(kind,id,data) VALUES(?,?,?) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (kind, object_id, self._serialize(value)),
            )
            self.connection.commit()
        return deepcopy(value)

    def _get(self, kind: str, object_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM objects WHERE kind=? AND id=?", (kind, object_id)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _list(self, kind: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM objects WHERE kind=? ORDER BY rowid", (kind,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _migrate_embedded_job_flows(self) -> None:
        rows = self.connection.execute(
            "SELECT id,data FROM objects WHERE kind='job' "
            "AND json_type(data, '$.flow_records') IS NOT NULL"
        ).fetchall()
        for job_id, raw in rows:
            job = json.loads(raw)
            records = job.pop("flow_records", [])
            self.connection.execute(
                "INSERT INTO job_flow_records(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO NOTHING",
                (job_id, self._serialize(records)),
            )
            self.connection.execute(
                "UPDATE objects SET data=? WHERE kind='job' AND id=?",
                (self._serialize(job), job_id),
            )

    def _migrate_embedded_job_signatures(self) -> None:
        rows = self.connection.execute(
            "SELECT id,data FROM objects WHERE kind='job' "
            "AND json_type(data, '$.payload_signatures') IS NOT NULL"
        ).fetchall()
        for job_id, raw in rows:
            job = json.loads(raw)
            signatures = job.pop("payload_signatures", [])
            self.connection.execute(
                "INSERT INTO job_payload_signatures(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO NOTHING",
                (job_id, self._serialize(signatures)),
            )
            self.connection.execute(
                "UPDATE objects SET data=? WHERE kind='job' AND id=?",
                (self._serialize(job), job_id),
            )

    def _save_job_parts(self, job: dict[str, Any]) -> None:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        self._put("job", job["id"], metadata)
        if "flow_records" in job:
            self.connection.execute(
                "INSERT INTO job_flow_records(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job["id"], self._serialize(job["flow_records"])),
            )
            self.connection.commit()
        if "payload_signatures" in job:
            self.connection.execute(
                "INSERT INTO job_payload_signatures(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job["id"], self._serialize(job["payload_signatures"])),
            )
            self.connection.commit()

    def ready(self) -> bool:
        try:
            return bool(self.connection.execute("SELECT 1").fetchone() == (1,))
        except sqlite3.Error:
            return False

    def close(self) -> None:
        self.connection.close()

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor", sensor["sensor_id"], sensor)

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor", sensor_id)

    def list_sensors(self) -> list[dict[str, Any]]:
        return self._list("sensor")

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return self._put("group", group["id"], group)

    def list_groups(self) -> list[dict[str, Any]]:
        return self._list("group")

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            row = self.connection.execute(
                "SELECT job_id FROM idempotency WHERE key=?", (job["idempotency_key"],)
            ).fetchone()
            if row:
                existing = self.get_job(row[0])
                if existing is None:
                    raise RuntimeError("idempotency ledger references missing job")
                return existing, False
            self._save_job_parts(job)
            self.connection.execute(
                "INSERT INTO idempotency(key,job_id) VALUES(?,?)",
                (job["idempotency_key"], job["id"]),
            )
            self.connection.commit()
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._save_job_parts(job)
            return deepcopy(job)

    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        return self._put("job", job["id"], metadata)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        job = self._get("job", job_id)
        if job is None:
            return None
        row = self.connection.execute(
            "SELECT data FROM job_flow_records WHERE job_id=?", (job_id,)
        ).fetchone()
        job["flow_records"] = json.loads(row[0]) if row else []
        row = self.connection.execute(
            "SELECT data FROM job_payload_signatures WHERE job_id=?", (job_id,)
        ).fetchone()
        job["payload_signatures"] = json.loads(row[0]) if row else []
        return job

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        return self._get("job", job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return self._list("job")

    def list_active_live_jobs(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM objects WHERE kind='job' "
            "AND json_extract(data, '$.mode')='LIVE' "
            "AND json_extract(data, '$.status') IN ('CAPTURING','UPLOADING') "
            "ORDER BY rowid"
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            job = self.get_job(job_id)
            if job is None:
                return False
            export_rows = self.connection.execute(
                "SELECT id FROM objects WHERE kind='export' AND json_extract(data, '$.job_id')=?",
                (job_id,),
            ).fetchall()
            export_ids = [str(row[0]) for row in export_rows]
            if export_ids:
                placeholders = ",".join("?" for _ in export_ids)
                self.connection.execute(
                    f"DELETE FROM export_blobs WHERE export_id IN ({placeholders})", export_ids
                )
                self.connection.execute(
                    f"DELETE FROM objects WHERE kind='export' AND id IN ({placeholders})",
                    export_ids,
                )
            self.connection.execute("DELETE FROM candidates WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM job_flow_records WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM job_payload_signatures WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM job_capture_blobs WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM idempotency WHERE job_id=?", (job_id,))
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='job' AND id=?", (job_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def save_job_capture(self, job_id: str, content: bytes) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO job_capture_blobs(job_id,content) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET content=excluded.content",
                (job_id, content),
            )
            self.connection.commit()

    def get_job_capture(self, job_id: str) -> bytes | None:
        row = self.connection.execute(
            "SELECT content FROM job_capture_blobs WHERE job_id=?", (job_id,)
        ).fetchone()
        return bytes(row[0]) if row else None

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO candidates(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job_id, self._serialize(candidates)),
            )
            self.connection.commit()

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        row = self.connection.execute(
            "SELECT data FROM candidates WHERE job_id=?", (job_id,)
        ).fetchone()
        return json.loads(row[0]) if row else []

    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            existing = self.connection.execute(
                "SELECT data FROM ai_analysis_runs WHERE analysis_job_id=? AND idempotency_key=?",
                (run["analysis_job_id"], run["idempotency_key"]),
            ).fetchone()
            if existing is not None:
                return json.loads(existing[0]), False
            self.connection.execute(
                "INSERT INTO ai_analysis_runs"
                "(run_id,analysis_job_id,idempotency_key,created_at,data) VALUES(?,?,?,?,?)",
                (
                    run["id"],
                    run["analysis_job_id"],
                    run["idempotency_key"],
                    run["created_at"],
                    self._serialize(run),
                ),
            )
            self.connection.commit()
            return deepcopy(run), True

    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            row = self.connection.execute(
                "SELECT data FROM ai_analysis_runs WHERE run_id=?", (run["id"],)
            ).fetchone()
            if row is not None:
                existing = json.loads(row[0])
                if existing.get("status") in {"COMPLETED", "FAILED", "CANCELLED"}:
                    return existing
            self.connection.execute(
                "UPDATE ai_analysis_runs SET data=? WHERE run_id=?",
                (self._serialize(run), run["id"]),
            )
            self.connection.commit()
            return deepcopy(run)

    def get_ai_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM ai_analysis_runs WHERE run_id=?", (run_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_analysis_runs WHERE analysis_job_id=? ORDER BY created_at DESC",
            (job_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT OR IGNORE INTO ai_candidate_assessments"
                "(assessment_id,ai_run_id,created_at,data) VALUES(?,?,?,?)",
                (
                    assessment["id"],
                    assessment["ai_run_id"],
                    assessment["created_at"],
                    self._serialize(assessment),
                ),
            )
            self.connection.commit()
            stored = self.get_ai_assessment(assessment["id"])
            if stored is None:
                raise RuntimeError("AI assessment was not persisted")
            return stored

    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM ai_candidate_assessments WHERE assessment_id=?",
            (assessment_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_candidate_assessments WHERE ai_run_id=? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT INTO ai_generated_artifacts"
                "(artifact_id,assessment_id,created_at,data) VALUES(?,?,?,?) "
                "ON CONFLICT(artifact_id) DO UPDATE SET data=excluded.data",
                (
                    artifact["id"],
                    artifact["assessment_id"],
                    artifact["created_at"],
                    self._serialize(artifact),
                ),
            )
            self.connection.commit()
            return deepcopy(artifact)

    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM ai_generated_artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_generated_artifacts "
            "WHERE assessment_id=? ORDER BY created_at,artifact_id",
            (assessment_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT OR IGNORE INTO ai_feedback"
                "(feedback_id,assessment_id,created_at,data) VALUES(?,?,?,?)",
                (
                    feedback["id"],
                    feedback["assessment_id"],
                    feedback["created_at"],
                    self._serialize(feedback),
                ),
            )
            self.connection.commit()
        return deepcopy(feedback)

    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_feedback WHERE assessment_id=? ORDER BY created_at,feedback_id",
            (assessment_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO audit_events(kind,object_id,occurred_at,data) VALUES(?,?,?,?)",
                (kind, object_id, datetime.now().astimezone().isoformat(), self._serialize(data)),
            )
            self.connection.commit()

    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]:
        rows = self.connection.execute("SELECT job_id,data FROM candidates").fetchall()
        return {str(job_id): json.loads(data) for job_id, data in rows}

    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-decision", decision["id"], decision)

    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-decision")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-ti-lookup", lookup["id"], lookup)

    def list_candidate_ti_lookups(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-ti-lookup")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-misp-action", action["id"], action)

    def list_candidate_misp_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-misp-action")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def update_candidate(self, candidate_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a candidate by ID across all jobs."""
        with self._lock:
            # Find which job contains this candidate
            for row in self.connection.execute("SELECT job_id,data FROM candidates"):
                job_id = row[0]
                candidates_list = json.loads(row[1])

                for i, candidate in enumerate(candidates_list):
                    if candidate.get("id") == candidate_id:
                        # Found it - need to update
                        from datetime import UTC

                        updates_copy = deepcopy(updates)

                        updated = deepcopy(candidate)

                        if "score_adjustment" in updates_copy:
                            old_score = updated.get("score", 0)
                            adj = updates_copy.pop("score_adjustment")
                            updated["score"] = max(0, min(100, old_score + adj))

                        if "exclude_reason" in updates_copy:
                            updated["excluded"] = True
                            updated["exclude_reason"] = updates_copy.pop("exclude_reason")

                        for key, value in updates_copy.items():
                            updated[key] = deepcopy(value)

                        updated["updated_at"] = datetime.now(UTC).isoformat()

                        candidates_list[i] = updated
                        self.connection.execute("DELETE FROM candidates WHERE job_id=?", (job_id,))
                        self.connection.execute(
                            "INSERT INTO candidates(job_id,data) VALUES(?,?)",
                            (job_id, self._serialize(candidates_list)),
                        )
                        self.connection.commit()
                        return deepcopy(updated)
        return None

    def delete_candidate(self, candidate_id: str) -> bool:
        """Delete a candidate by ID across all jobs."""
        with self._lock:
            for row in list(self.connection.execute("SELECT job_id,data FROM candidates")):
                job_id = row[0]
                candidates_list = json.loads(row[1])

                original_len = len(candidates_list)
                candidates_list = [c for c in candidates_list if c.get("id") != candidate_id]

                if len(candidates_list) < original_len:
                    self.connection.execute("DELETE FROM candidates WHERE job_id=?", (job_id,))
                    self.connection.execute(
                        "INSERT INTO candidates(job_id,data) VALUES(?,?)",
                        (job_id, self._serialize(candidates_list)),
                    )
                    self.connection.commit()
                    return True
            return False

    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]:
        return self._put("flow_label", label["id"], label)

    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]:
        labels = self._list("flow_label")
        if job_id is not None:
            labels = [label for label in labels if label.get("job_id") == job_id]
        return sorted(labels, key=lambda item: str(item["created_at"]))

    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]:
        return self._put("payload_signature", signature["id"], signature)

    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None:
        return self._get("payload_signature", signature_id)

    def list_payload_signatures(self) -> list[dict[str, Any]]:
        return sorted(
            self._list("payload_signature"),
            key=lambda item: str(item["created_at"]),
        )

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        return self._put("allowlist", entry["id"], entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return self._list("allowlist")

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='allowlist' AND id=?", (entry_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]:
        with self._lock:
            self._put("export", export["id"], export)
            self.connection.execute(
                "INSERT INTO export_blobs(export_id,content) VALUES(?,?) "
                "ON CONFLICT(export_id) DO UPDATE SET content=excluded.content",
                (export["id"], content),
            )
            self.connection.commit()
            return deepcopy(export)

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        metadata = self._get("export", export_id)
        row = self.connection.execute(
            "SELECT content FROM export_blobs WHERE export_id=?", (export_id,)
        ).fetchone()
        return (metadata, bytes(row[0])) if metadata is not None and row else None

    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]:
        stored, status = self.save_sensor_pcap_limited(segment, content, None)
        if stored is None or status not in {"OK", "EXISTS"}:
            raise RuntimeError(f"sensor PCAP save failed: {status}")
        return stored

    def save_sensor_pcap_limited(
        self, segment: dict[str, Any], content: bytes, max_total_bytes: int | None
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                row = self.connection.execute(
                    "SELECT data FROM objects WHERE kind='sensor_pcap' AND id=?",
                    (segment["id"],),
                ).fetchone()
                if row is not None:
                    existing = json.loads(row[0])
                    matches = all(
                        existing.get(field) == segment.get(field)
                        for field in ("sensor_id", "analysis_job_id", "sha256")
                    )
                    self.connection.commit()
                    return (existing, "EXISTS") if matches else (None, "CONFLICT")
                analysis_job_id = segment.get("analysis_job_id")
                if max_total_bytes is not None and analysis_job_id is not None:
                    used_row = self.connection.execute(
                        "SELECT COALESCE("
                        "SUM(CAST(json_extract(data, '$.size_bytes') AS INTEGER)),0) "
                        "FROM objects WHERE kind='sensor_pcap' "
                        "AND json_extract(data, '$.analysis_job_id')=?",
                        (analysis_job_id,),
                    ).fetchone()
                    used = int(used_row[0] if used_row else 0)
                    if used + len(content) > max_total_bytes:
                        self.connection.commit()
                        return None, "LIMIT"
                self.connection.execute(
                    "INSERT INTO objects(kind,id,data) VALUES('sensor_pcap',?,?)",
                    (segment["id"], self._serialize(segment)),
                )
                self.connection.execute(
                    "INSERT INTO sensor_pcap_blobs(segment_id,content) VALUES(?,?)",
                    (segment["id"], content),
                )
                self.connection.commit()
                return deepcopy(segment), "OK"
            except Exception:
                self.connection.rollback()
                raise

    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None:
        metadata = self._get("sensor_pcap", segment_id)
        row = self.connection.execute(
            "SELECT content FROM sensor_pcap_blobs WHERE segment_id=?", (segment_id,)
        ).fetchone()
        return (metadata, bytes(row[0])) if metadata is not None and row else None

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        return self._list("sensor_pcap")

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self._put("enrollment", enrollment["enrollment_id"], enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        return self._get("enrollment", enrollment_id)

    def list_enrollments(self) -> list[dict[str, Any]]:
        return self._list("enrollment")

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            row = self.connection.execute(
                "SELECT id,data FROM objects WHERE kind='enrollment' "
                "AND json_extract(data, '$.token_hash')=?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None, "NOT_FOUND"
            enrollment = json.loads(row[1])
            if enrollment.get("revoked_at") is not None:
                return enrollment, "REVOKED"
            if enrollment.get("claimed_at") is not None:
                return enrollment, "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                return enrollment, "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            self._put("enrollment", str(row[0]), enrollment)
            return enrollment, "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor_credential", credential["sensor_id"], credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor_credential", sensor_id)

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            sensor = self.get_sensor(sensor_id)
            if sensor is None:
                return None, "NOT_FOUND"
            if sensor.get("config_version") != expected_version:
                return sensor, "CONFLICT"
            sensor.update(configuration)
            sensor["config_version"] = expected_version + 1
            return self.upsert_sensor(sensor), "OK"

    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None:
        with self._lock:
            sensor = self.get_sensor(sensor_id)
            if sensor is None:
                return None
            sensor.update(fields)
            return self.upsert_sensor(sensor)

    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            try:
                if preset.get("is_default"):
                    rows = self.connection.execute(
                        "SELECT id,data FROM objects WHERE kind='detector_weight_preset'"
                    ).fetchall()
                    for object_id, raw in rows:
                        item = json.loads(raw)
                        item["is_default"] = False
                        self.connection.execute(
                            "UPDATE objects SET data=? "
                            "WHERE kind='detector_weight_preset' AND id=?",
                            (self._serialize(item), object_id),
                        )
                self.connection.execute(
                    "INSERT INTO objects(kind,id,data) VALUES(?,?,?) "
                    "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                    ("detector_weight_preset", preset["id"], self._serialize(preset)),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            return deepcopy(preset)

    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        return self._get("detector_weight_preset", preset_id)

    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None:
        with self._lock:
            try:
                preset = self.get_detector_weight_preset(preset_id)
                if preset is None:
                    return None
                preset.update(updates)
                if set_as_default:
                    rows = self.connection.execute(
                        "SELECT id,data FROM objects WHERE kind='detector_weight_preset'"
                    ).fetchall()
                    for object_id, raw in rows:
                        item = json.loads(raw)
                        item["is_default"] = object_id == preset_id
                        if object_id == preset_id:
                            item.update(updates)
                            preset = item
                        self.connection.execute(
                            "UPDATE objects SET data=? "
                            "WHERE kind='detector_weight_preset' AND id=?",
                            (self._serialize(item), object_id),
                        )
                else:
                    self.connection.execute(
                        "UPDATE objects SET data=? WHERE kind='detector_weight_preset' AND id=?",
                        (self._serialize(preset), preset_id),
                    )
                self.connection.commit()
                return deepcopy(preset)
            except Exception:
                self.connection.rollback()
                raise

    def list_detector_weight_presets(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._list("detector_weight_preset")

    def delete_detector_weight_preset(self, preset_id: str) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='detector_weight_preset' AND id=?", (preset_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        with self._lock:
            try:
                selected = self.get_detector_weight_preset(preset_id)
                if selected is None:
                    return None
                presets = self.list_detector_weight_presets()
                for preset in presets:
                    preset["is_default"] = preset["id"] == preset_id
                    self.connection.execute(
                        "UPDATE objects SET data=? WHERE kind='detector_weight_preset' AND id=?",
                        (self._serialize(preset), preset["id"]),
                    )
                self.connection.commit()
                return next(preset for preset in presets if preset["id"] == preset_id)
            except Exception:
                self.connection.rollback()
                raise
