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
    inline_flow_records_enabled: bool | None = None
    # This only enables the explicitly limited development token minting endpoint.
    # It does not install production authentication or authorization middleware.
    dev_login_enabled: bool = False
    dev_token_ttl_seconds: int = Field(default=900, gt=0, le=3600)

    @model_validator(mode="after")
    def compatibility_defaults(self) -> "Settings":
        if self.inline_flow_records_enabled is None:
            self.inline_flow_records_enabled = self.environment == "test"
        return self
