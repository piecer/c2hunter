import importlib
import secrets
import sqlite3
import sys
import uuid

import pytest
import test_account_auth_store as support

PASSWORD = support.PASSWORD
module = support.module
store = support.store
admin = support.admin


def test_standalone_cli_init_bootstrap_reset_getpass_and_no_app(tmp_path, monkeypatch, capsys):
    cli = importlib.import_module("c2hunter_controller.auth_cli")
    private = tmp_path / "private"
    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "memory://")
    monkeypatch.setenv("C2HUNTER_AUTH_DATABASE_PATH", str(private / "auth.sqlite3"))
    assert cli.main(["init"]) == 0
    answers = iter([PASSWORD, PASSWORD, PASSWORD + " reset", PASSWORD + " reset"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["bootstrap", "admin"]) == 0
    current = module().AuthStore(sqlite_path=private / "auth.sqlite3")
    old = current.login("admin", PASSWORD)
    assert cli.main(["reset-password", "admin"]) == 0
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        current.authenticate(old.token)
    assert current.login("admin", PASSWORD + " reset").user.must_change_password
    import subprocess

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; import c2hunter_controller.auth_cli; "
            "assert 'c2hunter_controller.app' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert probe.returncode == 0
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    with pytest.raises(SystemExit):
        cli.main(["bootstrap", "other", "--password", PASSWORD])


def test_cli_password_mismatch_and_memory_reconcile_fail_closed(store, admin, monkeypatch, capsys):
    cli = importlib.import_module("c2hunter_controller.auth_cli")
    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "memory://")
    monkeypatch.setenv("C2HUNTER_AUTH_DATABASE_PATH", str(store.sqlite_path))
    answers = iter([PASSWORD, PASSWORD + " mismatch"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["reset-password", "admin"]) == 2
    assert store.authenticate(admin.token)
    assert cli.main(["reconcile-audit", "--limit", "100"]) == 2
    assert "AUDIT_RECONCILE_UNSUPPORTED" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["reconcile-audit", "--limit", "1001"])


def test_bounded_reconciliation_hook_only_proven_terminal_records(store, admin):
    cli = importlib.import_module("c2hunter_controller.auth_cli")
    resources = [str(uuid.uuid4()) for _ in range(3)]
    for resource in resources:
        store.reserve_job(
            "analysis", resource, admin.actor, str(uuid.uuid4()), secrets.token_hex(16)
        )
    states = dict(zip(resources, ["COMPLETED", "ANALYZING", None], strict=True))
    result = cli.reconcile(store, lambda link: states[link.resource_id], limit=3)
    assert result == dict(examined=3, completed=1, pending=2, next_cursor=None)
    assert store.job_audit_status("analysis", resources[0]) == "complete"
    assert store.job_audit_status("analysis", resources[1]) == "pending"
    with sqlite3.connect(store.sqlite_path) as db:
        assert (
            db.execute("SELECT count(*) FROM auth_audit WHERE action='audit.reconcile'").fetchone()[
                0
            ]
            == 1
        )
