from pathlib import Path

import pytest
from pydantic import ValidationError

from c2hunter_controller.config import Settings


def test_account_defaults_and_factory(tmp_path: Path) -> None:
    from c2hunter_controller.auth_runtime import build_auth_store

    assert Settings(environment="test").account_auth_enabled is False
    assert build_auth_store(Settings(environment="test")) is None
    path = tmp_path / "private" / "auth.sqlite3"
    settings = Settings(environment="development", auth_database_path=str(path))
    assert settings.account_auth_enabled is True
    store = build_auth_store(settings)
    assert store is not None
    assert not path.exists()


@pytest.mark.parametrize(
    "values",
    [
        {"account_auth_enabled": True, "api_auth_required": False},
        {"account_auth_enabled": True, "dev_login_enabled": True},
        {"account_auth_enabled": False, "api_auth_required": False},
        {"auth_public_origin": "http://example.com"},
        {"auth_public_origin": "https://example.com/path"},
        {"auth_public_origin": "https://user:pass@example.com"},
        {"auth_public_origin": "https://EXAMPLE.com"},
        {"auth_public_origin": "https://example.com\\evil"},
        {"auth_public_origin": "https://example..com"},
        {"auth_public_origin": "https://example.com:0"},
        {"auth_public_origin": "https://example.com/"},
        {"auth_public_origin": "http://127.0.0.1:9001"},
        {"viewer_token_sha256": "a" * 64, "admin_token_sha256": "a" * 64},
    ],
)
def test_insecure_settings_rejected(values: dict) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="development", **values)


def test_pg_factory_uses_application_dsn_without_sqlite(tmp_path: Path) -> None:
    from c2hunter_controller.auth_runtime import build_auth_store

    dsn = "postgresql://auth_fixture@127.0.0.1:1/never_connect"
    store = build_auth_store(
        Settings(
            environment="test",
            account_auth_enabled=True,
            api_auth_required=True,
            database_url=dsn,
            auth_database_path=str(tmp_path / "unused.sqlite3"),
        )
    )
    assert store is not None
    assert store.db.dsn == dsn
    assert store.db.path is None
    assert not (tmp_path / "unused.sqlite3").exists()


def test_empty_origin_is_setup_not_invalid() -> None:
    assert Settings(auth_public_origin="").auth_public_origin is None


def test_proxy_preserves_public_port() -> None:
    config = (Path(__file__).parents[2] / "web/nginx.conf").read_text()
    assert "proxy_set_header Host $http_host;" in config
    assert "X-Frame-Options" in config


def test_explicit_loopback_and_legacy() -> None:
    assert Settings(
        environment="development",
        auth_public_origin="http://127.0.0.1:9001",
        auth_insecure_loopback_http=True,
    ).account_auth_enabled
    assert Settings(account_auth_enabled=False, api_auth_required=True)
