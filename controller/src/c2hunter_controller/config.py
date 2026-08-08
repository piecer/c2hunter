from pydantic import Field, model_validator
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
