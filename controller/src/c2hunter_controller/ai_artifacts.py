from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from .ai_analysis import CandidateAssessment, CandidateEvidenceBundle


class AIArtifactError(ValueError):
    """Raised when an AI-generated draft violates an artifact safety policy."""


class SplunkDataProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["c2hunter_flow_v1"] = "c2hunter_flow_v1"
    index: str = "c2hunter"
    sourcetype: str = "c2hunter:flow"
    fields: dict[str, str] = Field(
        default_factory=lambda: {
            "timestamp": "_time",
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
            "src_port": "src_port",
            "dst_port": "dst_port",
            "protocol": "protocol",
            "direction": "direction",
            "payload_hash": "payload_hash",
            "payload_length": "payload_length",
            "packet_count": "packet_count",
            "total_bytes": "total_bytes",
            "sensor_id": "sensor_id",
        }
    )


class SplunkDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: Literal["c2hunter_flow_v1"] = "c2hunter_flow_v1"
    name: str = Field(min_length=1, max_length=300)
    spl: str = Field(min_length=1, max_length=10000)
    purpose: str = Field(min_length=1, max_length=1000)
    expected_fields: list[str] = Field(min_length=1, max_length=50)
    evidence_ids: list[str] = Field(min_length=1, max_length=50)
    schedule_recommendation: str | None = Field(default=None, max_length=100)
    lookback: str | None = Field(default=None, max_length=100)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    throttle_fields: list[str] = Field(default_factory=list, max_length=20)
    false_positive_notes: list[str] = Field(default_factory=list, max_length=20)


class MispTag(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=300)


class MispAttribute(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["ip-dst", "domain", "sha256"]
    category: Literal["Network activity", "Payload delivery"]
    value: str = Field(min_length=1, max_length=512)
    to_ids: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    comment: str = Field(min_length=1, max_length=2000)


class MispEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    info: str = Field(min_length=1, max_length=1000)
    published: Literal[False]
    analysis: int = Field(default=0, ge=0, le=2)
    threat_level_id: int = Field(default=2, ge=1, le=4)
    distribution: int = Field(default=0, ge=0, le=5)
    Tag: list[MispTag] = Field(default_factory=list, max_length=20)
    Attribute: list[MispAttribute] = Field(min_length=1, max_length=100)


class MispDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    Event: MispEvent


class ArtifactRepository(Protocol):
    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None: ...
    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]: ...


_WRITE_COMMAND = re.compile(
    r"(?:^|\|)\s*(delete|collect|outputlookup|sendemail|script|run)\b", re.I
)
_IPV4_LITERAL = re.compile(r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.])")
_RFC1918 = tuple(ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _profile_fields(profile: SplunkDataProfile) -> set[str]:
    return set(profile.fields.values()) | {"event_count", "total_packets", "total_bytes_sum"}


def _command_fields(spl: str) -> set[str]:
    fields: set[str] = set()
    for segment in spl.split("|"):
        normalized = segment.strip()
        lowered = normalized.lower()
        if lowered.startswith("table "):
            fields.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", normalized[6:]))
        if " by " in lowered and lowered.startswith(("stats ", "timechart ")):
            offset = lowered.rfind(" by ") + 4
            fields.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", normalized[offset:]))
    return fields


def validate_splunk_draft(
    content: dict[str, Any], *, allowed_iocs: set[str], profile: SplunkDataProfile | None = None
) -> SplunkDraft:
    draft = SplunkDraft.model_validate(content)
    selected_profile = profile or SplunkDataProfile()
    if draft.profile != selected_profile.name:
        raise AIArtifactError("unknown Splunk data profile")
    if _WRITE_COMMAND.search(draft.spl):
        raise AIArtifactError("SPL write command is not allowed")
    if re.search(r"\bindex\s*=\s*\*", draft.spl, re.I):
        raise AIArtifactError("SPL index=* is not allowed")
    if "earliest=" not in draft.spl.lower() or "latest=" not in draft.spl.lower():
        raise AIArtifactError("SPL requires an explicit time range")
    used_fields = (
        set(draft.expected_fields) | set(draft.throttle_fields) | _command_fields(draft.spl)
    )
    unknown_fields = sorted(used_fields - _profile_fields(selected_profile))
    if unknown_fields:
        raise AIArtifactError(f"unknown profile field: {', '.join(unknown_fields)}")
    for literal in _IPV4_LITERAL.findall(draft.spl):
        try:
            normalized = str(ip_address(literal))
        except ValueError as exc:
            raise AIArtifactError("invalid IP literal in SPL") from exc
        if normalized not in allowed_iocs:
            raise AIArtifactError("SPL IOC literal is not present in supplied evidence")
    return draft


def _is_internal_ip(value: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in _RFC1918)


def validate_misp_draft(content: dict[str, Any], *, allowed_iocs: set[str]) -> MispDraft:
    try:
        draft = MispDraft.model_validate(content)
    except Exception as exc:
        if isinstance(content.get("Event"), dict) and content["Event"].get("published") is True:
            raise AIArtifactError("MISP draft must keep published=false") from exc
        raise AIArtifactError(f"invalid MISP draft: {exc}") from exc
    if draft.Event.published is not False:
        raise AIArtifactError("MISP draft must keep published=false")
    for attribute in draft.Event.Attribute:
        if attribute.value not in allowed_iocs:
            raise AIArtifactError("MISP attribute is not present in supplied evidence")
        if _is_internal_ip(attribute.value):
            raise AIArtifactError("MISP draft cannot contain an internal IP")
        if (
            attribute.first_seen
            and attribute.last_seen
            and attribute.first_seen > attribute.last_seen
        ):
            raise AIArtifactError("MISP first_seen must not be after last_seen")
    return draft


def _splunk_content(
    *, bundle: CandidateEvidenceBundle, detection: bool, profile: SplunkDataProfile
) -> dict[str, Any]:
    ip = bundle.candidate.external_ip
    evidence_ids = [item.evidence_id for item in bundle.evidence]
    base = (
        f'index={profile.index} sourcetype="{profile.sourcetype}" earliest=-15m latest=now '
        f'(src_ip="{ip}" OR dst_ip="{ip}")'
    )
    if detection:
        spl = (
            f"{base} | stats count AS event_count sum(packet_count) AS total_packets "
            "by dst_ip,dst_port,protocol | where event_count >= 5"
        )
        return SplunkDraft(
            name=f"C2Hunter scheduled review for {ip}",
            spl=spl,
            purpose="Detect repeated traffic matching a validated C2Hunter candidate context.",
            expected_fields=["dst_ip", "dst_port", "protocol", "event_count", "total_packets"],
            evidence_ids=evidence_ids,
            schedule_recommendation="*/5 * * * *",
            lookback="-15m to now",
            severity="medium",
            throttle_fields=["dst_ip", "dst_port"],
            false_positive_notes=["Validate approved services and maintenance traffic."],
        ).model_dump(mode="json")
    spl = (
        f"{base} | stats count AS event_count sum(packet_count) AS total_packets "
        "sum(total_bytes) AS total_bytes_sum by src_ip,dst_ip,dst_port,protocol"
    )
    return SplunkDraft(
        name=f"C2Hunter evidence hunt for {ip}",
        spl=spl,
        purpose="Review timing and volume around the supplied candidate without modifying data.",
        expected_fields=[
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "event_count",
            "total_packets",
            "total_bytes_sum",
        ],
        evidence_ids=evidence_ids,
    ).model_dump(mode="json")


def _misp_content(
    *,
    assessment: CandidateAssessment,
    bundle: CandidateEvidenceBundle,
    ai_run_id: str,
    analysis_job_id: str,
) -> dict[str, Any]:
    external_ip = bundle.candidate.external_ip
    evidence_ids = [item.evidence_id for item in bundle.evidence]
    attribute = MispAttribute(
        type="ip-dst",
        category="Network activity",
        value=external_ip,
        to_ids=(
            assessment.candidate.verdict == "LIKELY_C2" and assessment.candidate.confidence >= 0.8
        ),
        first_seen=bundle.candidate.first_seen,
        last_seen=bundle.candidate.last_seen,
        comment=(
            f"C2Hunter job={analysis_job_id}, AI run={ai_run_id}, evidence={','.join(evidence_ids)}"
        ),
    )
    return MispDraft(
        Event=MispEvent(
            info=f"C2Hunter suspected C2 candidate {external_ip}",
            published=False,
            Tag=[
                MispTag(name=f"c2hunter:ai-verdict={assessment.candidate.verdict.lower()}"),
                MispTag(name="c2hunter:review-status=pending"),
            ],
            Attribute=[attribute],
        )
    ).model_dump(mode="json")


def build_ai_artifacts(
    *,
    assessment_id: str,
    ai_run_id: str,
    analysis_job_id: str,
    assessment: CandidateAssessment,
    bundle: CandidateEvidenceBundle,
) -> list[dict[str, Any]]:
    profile = SplunkDataProfile()
    allowed_iocs = {bundle.candidate.external_ip}
    contents = [
        ("SPLUNK_HUNT", _splunk_content(bundle=bundle, detection=False, profile=profile)),
        ("SPLUNK_DETECTION", _splunk_content(bundle=bundle, detection=True, profile=profile)),
        (
            "MISP_DRAFT",
            _misp_content(
                assessment=assessment,
                bundle=bundle,
                ai_run_id=ai_run_id,
                analysis_job_id=analysis_job_id,
            ),
        ),
    ]
    created_at = datetime.now(UTC).isoformat()
    artifacts: list[dict[str, Any]] = []
    for artifact_type, content in contents:
        if artifact_type.startswith("SPLUNK"):
            validate_splunk_draft(content, allowed_iocs=allowed_iocs, profile=profile)
        else:
            validate_misp_draft(content, allowed_iocs=allowed_iocs)
        artifacts.append(
            {
                "id": str(uuid.uuid4()),
                "assessment_id": assessment_id,
                "ai_run_id": ai_run_id,
                "analysis_job_id": analysis_job_id,
                "artifact_type": artifact_type,
                "schema_version": "1.0",
                "content": content,
                "validation_status": "VALID",
                "approved_status": "PENDING",
                "created_at": created_at,
            }
        )
    return artifacts


class AIArtifactService:
    def __init__(self, repository: ArtifactRepository) -> None:
        self.repository = repository

    def generate(self, **kwargs: Any) -> list[dict[str, Any]]:
        return [self.repository.save_ai_artifact(item) for item in build_ai_artifacts(**kwargs)]

    def list(self, assessment_id: str) -> list[dict[str, Any]]:
        return self.repository.list_ai_artifacts(assessment_id)

    def review(
        self,
        artifact_id: str,
        *,
        status: Literal["APPROVED", "REJECTED"],
        reviewed_by: str,
        note: str = "",
    ) -> dict[str, Any]:
        artifact = self.repository.get_ai_artifact(artifact_id)
        if artifact is None:
            raise AIArtifactError("AI artifact not found")
        current = artifact.get("approved_status")
        if current == status:
            return artifact
        if current != "PENDING":
            raise AIArtifactError("AI artifact review status is terminal")
        updated = {
            **artifact,
            "approved_status": status,
            "approved_by": reviewed_by,
            "approved_at": datetime.now(UTC).isoformat(),
            "review_note": note,
        }
        return self.repository.save_ai_artifact(cast(dict[str, Any], updated))
