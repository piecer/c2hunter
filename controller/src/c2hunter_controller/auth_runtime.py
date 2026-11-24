"""Persistent auth construction shared by HTTP and workers; never migrates."""

from .auth_store import AuthStore
from .config import Settings


def build_auth_store(settings: Settings) -> AuthStore | None:
    if not settings.account_auth_enabled:
        return None
    if settings.database_url == "memory://":
        return AuthStore(sqlite_path=settings.auth_database_path)
    return AuthStore(database_url=settings.database_url)
