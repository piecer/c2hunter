from typing import Literal

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
    inline_flow_records_enabled: bool | None = None
    # This only enables the explicitly limited development token minting endpoint.
    # Production deployments should use pre-hashed static tokens or a future OIDC integration.
    dev_login_enabled: bool = False
    dev_token_ttl_seconds: int = Field(default=900, gt=0, le=3600)
    api_auth_required: bool | None = None
    viewer_token_sha256: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    analyst_token_sha256: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    admin_token_sha256: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    rate_limit_window_seconds: int = Field(default=60, gt=0, le=3600)
    dev_login_rate_limit: int = Field(default=10, gt=0)
    enrollment_claim_rate_limit: int = Field(default=10, gt=0)
    analysis_job_rate_limit: int = Field(default=30, gt=0)
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
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    threat_intel_timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    abuseipdb_max_age_days: int = Field(default=90, ge=1, le=365)
    misp_url: str = ""
    misp_api_key: SecretStr = SecretStr("")
    misp_verify_tls: bool = True
    misp_default_event_id: str = Field(default="", max_length=100)

    @model_validator(mode="after")
    def compatibility_defaults(self) -> "Settings":
        if self.inline_flow_records_enabled is None:
            self.inline_flow_records_enabled = self.environment == "test"
        if self.api_auth_required is None:
            # Unit tests use isolated in-memory repositories; deployable modes are closed.
            self.api_auth_required = self.environment != "test"
        return self

    @model_validator(mode="after")
    def reject_dev_login_in_production(self) -> "Settings":
        if self.dev_login_enabled and self.environment not in {"development", "test"}:
            raise ValueError(
                f"dev_login_enabled=True is not allowed in environment='{self.environment}'. "
                "Disable C2HUNTER_DEV_LOGIN_ENABLED or use static hashed tokens instead."
            )
        return self
