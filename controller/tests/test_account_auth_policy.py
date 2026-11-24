"""Closed account-mode route policy; legacy bearer/device code stays separate."""

from importlib import import_module, util

import pytest

from c2hunter_controller.security import Role


def policy():
    name = "c2hunter_controller.auth_policy"
    assert util.find_spec(name) is not None, "account-mode policy must exist"
    return import_module(name)


@pytest.mark.parametrize(
    ("method", "path", "access", "role", "external"),
    [
        ("GET", "/api/v1/dashboard", "principal", Role.VIEWER, False),
        ("POST", "/api/v1/analysis-jobs", "principal", Role.ANALYST, False),
        ("GET", "/api/v1/integration-settings", "principal", Role.ADMIN, False),
        ("GET", "/api/v1/ai-capabilities", "principal", Role.ANALYST, True),
        ("GET", "/api/v1/ai-investigations/capabilities", "principal", Role.ANALYST, False),
        ("POST", "/api/v1/sensors/fixture/heartbeat", "device", None, False),
        ("POST", "/api/v1/sensor-enrollments/fixture/claim", "device", None, False),
        ("GET", "/api/v1/sensors/fixture/agent-config", "device", None, False),
        ("PUT", "/api/v1/sensors/fixture/pcap-segments/part", "device", None, False),
        ("GET", "/api/v1/health", "public", None, False),
        ("POST", "/api/v1/auth/dev-login", "disabled", None, False),
        ("GET", "/api/v1/auth/csrf", "public", None, False),
        ("POST", "/api/v1/auth/login", "public", None, False),
        ("GET", "/api/v1/auth/me", "principal", Role.VIEWER, False),
        ("POST", "/api/v1/auth/password", "session", Role.VIEWER, False),
        ("GET", "/api/v1/auth/activity", "session", Role.VIEWER, False),
        ("POST", "/api/v1/admin/users", "session", Role.ADMIN, False),
        ("PATCH", "/api/v1/admin/users/fixture", "session", Role.ADMIN, False),
        ("POST", "/api/v1/admin/users/fixture/reset-password", "session", Role.ADMIN, False),
        ("POST", "/api/v1/admin/audit/export", "session", Role.ADMIN, False),
        ("GET", "/docs", "principal", Role.VIEWER, False),
        ("HEAD", "/openapi.json", "principal", Role.VIEWER, False),
    ],
)
def test_exact_reviewed_roles_and_credential_planes(method, path, access, role, external):
    rule = policy().lookup_rule(method, path)
    assert rule is not None
    assert (rule.access, rule.minimum_role, rule.external_read) == (access, role, external)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/future-sensitive-handler"),
        ("POST", "/api/v1/future-sensitive-handler"),
        ("PATCH", "/api/v1/auth/login"),
        ("TRACE", "/api/v1/dashboard"),
        ("OPTIONS", "/api/v1/admin/users"),
        ("GET", "/api/v1/sensors/a/agent-config/../configuration"),
        ("GET", "/api/v1/sensors/a/agent-config/extra"),
        ("POST", "/api/v1/auth/login/../admin/users"),
        ("GET", "/api/v1//dashboard"),
        ("GET", "/api/v1/dashboard/"),
        ("get", "/api/v1/dashboard"),
    ],
)
def test_unknown_methods_and_paths_never_inherit_a_role(method, path):
    assert policy().lookup_rule(method, path) is None


def test_audit_uses_route_template_not_enrollment_credential():
    rule = policy().lookup_rule("POST", "/api/v1/sensor-enrollments/private-fixture/claim")
    assert rule.template == "/api/v1/sensor-enrollments/{token}/claim"
    assert "private-fixture" not in rule.template


def test_only_required_self_service_allows_forced_password_change():
    allowed = {
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/auth/csrf"),
        ("POST", "/api/v1/auth/password"),
        ("POST", "/api/v1/auth/logout"),
    }
    actual = {(rule.method, rule.template) for rule in policy().RULES if rule.forced_change}
    assert actual == allowed


def test_closed_catalog_has_unique_methods_and_templates():
    rules = policy().RULES
    assert len({(rule.method, rule.template) for rule in rules}) == len(rules)
    assert all(
        rule.minimum_role is not None for rule in rules if rule.access in {"session", "principal"}
    )


def test_registered_explicit_api_operations_have_reviewed_policy():
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    app = create_app(Settings(environment="test"))
    catalog = {(rule.method, rule.template) for rule in policy().RULES}
    operations = {
        (method, getattr(route, "path", ""))
        for route in app.routes
        if getattr(route, "path", "").startswith("/api/v1/")
        for method in getattr(route, "methods", ())
    }
    assert operations
    assert operations <= catalog
