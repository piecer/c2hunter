from ipaddress import ip_address, ip_network
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="C2HUNTER_", extra="ignore")

    service_name: str = "c2hunter-controller"
    environment: str = "development"
    clock_skew_threshold_seconds: float = Field(default=2.0, gt=0)
    heartbeat_timeout_seconds: int = Field(default=30, gt=0)
    database_url: str = "memory://"
    redis_url: str = "memory://"
    clickhouse_url: str = "memory://"
    clickhouse_database: str = "c2hunter"
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    s3_endpoint: str = "memory://"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_bucket: str = "c2hunter"
    queue_visibility_timeout_seconds: int = Field(default=300, gt=0)
    flow_ingestion_grace_seconds: int = Field(default=65, ge=0)
    pcap_upload_max_bytes: int = Field(default=500 * 1024 * 1024, gt=0)
    pcap_upload_max_packets: int = Field(default=2_000_000, gt=0)
    pcap_export_max_bytes: int | None = Field(default=None, ge=24)
    pcap_export_scan_max_bytes: int | None = Field(default=None, gt=0)
    pcap_export_scan_max_packets: int | None = Field(default=None, gt=0)
    pcap_export_max_concurrent: int = Field(default=1, ge=1, le=16)
    inline_flow_records_enabled: bool | None = None
    # This only enables the explicitly limited development token minting endpoint.
    # Production deployments should use pre-hashed static tokens or a future OIDC integration.
    dev_login_enabled: bool = False
    dev_token_ttl_seconds: int = Field(default=28_800, gt=0, le=86_400)
    api_auth_required: bool | None = None
    viewer_token_sha256: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    analyst_token_sha256: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    admin_token_sha256: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    rate_limit_window_seconds: int = Field(default=60, gt=0, le=3600)
    dev_login_rate_limit: int = Field(default=10, gt=0)
    enrollment_claim_rate_limit: int = Field(default=10, gt=0)
    analysis_job_rate_limit: int = Field(default=30, gt=0)
    trusted_proxy_cidrs: str = ""
    ai_analysis_enabled: bool = False
    ai_model_provider: Literal["fake", "ollama", "openai-compatible"] = "fake"
    ai_model_base_url: str = "http://127.0.0.1:11434"
    ai_model_name: str = "qwen3.6-agent:256k"
    ai_model_api_key: SecretStr = SecretStr("")
    ai_model_timeout_seconds: float = Field(default=120, gt=0, le=600)
    ai_model_retries: int = Field(default=1, ge=0, le=3)
    ai_model_temperature: float = Field(default=0.1, ge=0, le=1)
    ai_model_context_tokens: int = Field(default=16384, ge=8192, le=262144)
    ai_model_max_output_tokens: int = Field(default=4096, ge=512, le=16384)
    ai_metrics_port: int = Field(default=9102, ge=1024, le=65535)
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    threat_intel_timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    threat_intel_request_delay_seconds: float = Field(default=1.0, ge=0, le=60)
    abuseipdb_max_age_days: int = Field(default=90, ge=1, le=365)
    candidate_auto_enrichment_limit: int = Field(default=20, ge=0, le=200)
    candidate_auto_enrichment_workers: int = Field(default=4, ge=1, le=16)
    candidate_auto_enrichment_queue_capacity: int = Field(default=200, ge=1, le=2000)
    misp_url: str = ""
    misp_api_key: SecretStr = SecretStr("")
    misp_verify_tls: bool = True
    misp_default_event_id: str = Field(default="", max_length=100)

    @property
    def trusted_proxy_networks(self) -> tuple[str, ...]:
        return tuple(item.strip() for item in self.trusted_proxy_cidrs.split(",") if item.strip())

    @property
    def ai_model_endpoint_is_remote(self) -> bool:
        if self.ai_model_provider == "fake":
            return False
        host = urlsplit(self.ai_model_base_url).hostname
        if host in {"localhost", "localhost.localdomain", "host.docker.internal"}:
            return False
        try:
            address = ip_address(host or "")
        except ValueError:
            return True
        return not (address.is_private or address.is_loopback or address.is_link_local)

    @model_validator(mode="after")
    def compatibility_defaults(self) -> "Settings":
        if self.inline_flow_records_enabled is None:
            self.inline_flow_records_enabled = self.environment == "test"
        if self.api_auth_required is None:
            # Unit tests use isolated in-memory repositories; deployable modes are closed.
            self.api_auth_required = self.environment != "test"
        if self.pcap_export_max_bytes is None:
            self.pcap_export_max_bytes = self.pcap_upload_max_bytes
        if self.pcap_export_scan_max_bytes is None:
            self.pcap_export_scan_max_bytes = self.pcap_upload_max_bytes
        if self.pcap_export_scan_max_packets is None:
            self.pcap_export_scan_max_packets = self.pcap_upload_max_packets
        return self

    @model_validator(mode="after")
    def validate_network_boundaries(self) -> "Settings":
        try:
            for network in self.trusted_proxy_networks:
                ip_network(network, strict=False)
        except ValueError as exc:
            raise ValueError(f"trusted_proxy_cidrs contains an invalid network: {exc}") from exc

        endpoint = urlsplit(self.ai_model_base_url)
        if (
            endpoint.scheme not in {"http", "https"}
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
        ):
            raise ValueError(
                "ai_model_base_url must be an absolute HTTP(S) URL without embedded credentials"
            )
        return self

    @model_validator(mode="after")
    def reject_dev_login_in_production(self) -> "Settings":
        if self.dev_login_enabled and self.environment not in {"development", "test"}:
            raise ValueError(
                f"dev_login_enabled=True is not allowed in environment='{self.environment}'. "
                "Disable C2HUNTER_DEV_LOGIN_ENABLED or use static hashed tokens instead."
            )
        return self
