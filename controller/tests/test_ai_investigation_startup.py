"""Migration ownership and configured-not-probed compatibility."""

from fastapi.testclient import TestClient

from c2hunter_controller import migrate
from c2hunter_controller.ai_gateway import OpenAICompatibleGateway
from c2hunter_controller.ai_investigation_store import InvestigationRunStore
from c2hunter_controller.ai_investigation_worker import configured_service
from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_ai_investigation_http_runtime import BASE, CAPS, HEADERS, settings


def test_explicit_migration_command_initializes_investigation_after_base(monkeypatch):
    events = []

    class Repository:
        def __init__(self, *args):
            pass

        def initialize_schema(self, **kwargs):
            events.append("base")

    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "postgresql://not-used")
    monkeypatch.setattr(migrate, "PostgresRepository", Repository)
    monkeypatch.setattr(
        "c2hunter_controller.ai_investigation_store.initialize_investigation_store",
        lambda repo: events.append("investigation"),
    )
    assert migrate.main([]) == 0
    assert events == ["base", "investigation"]


def test_missing_store_is_unavailable_without_runtime_ddl(tmp_path):
    repo = SQLiteRepository(tmp_path / "not-initialized.db")
    sql = []
    repo.connection.set_trace_callback(sql.append)
    service, reason = configured_service(repo, None)
    assert service is None and reason == "STORE_NOT_INITIALIZED"
    assert not any("CREATE" in query or "INSERT" in query for query in sql)
    repo.close()


def test_local_bootstrap_persists_marker_and_indexes_without_provider_probe(tmp_path, monkeypatch):
    path = tmp_path / "bootstrap.db"
    repo = SQLiteRepository(path)
    gateway = OpenAICompatibleGateway(
        base_url="http://host.docker.internal:11434", model="not-probed"
    )
    monkeypatch.setattr(
        gateway, "ready", lambda: (_ for _ in ()).throw(AssertionError("readiness probe"))
    )
    app = create_app(settings(), repo, ai_gateway=gateway)
    with TestClient(app) as client:
        response = client.get(CAPS, headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["availability"] == "UNAVAILABLE"
        assert response.headers["x-investigation-unavailable-reason"] == "PROVIDER_UNSUPPORTED"
        assert client.get(BASE, headers=HEADERS).json() == {"items": [], "next_cursor": None}
        assert app.state.ai_analysis_service.gateway is gateway
    reopened = SQLiteRepository(path)
    assert InvestigationRunStore(reopened).page("owner", "job") == []
    names = {
        row[0]
        for row in reopened.connection.execute("SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert {"investigation_queue_v1", "investigation_owner_v1", "investigation_slot_v1"} <= names
    reopened.close()
    repo.close()


def test_accepted_provider_without_dispatch_is_unavailable_no_ready_probe(monkeypatch):
    repo = MemoryRepository()
    gateway = OpenAICompatibleGateway(base_url="http://127.0.0.1:1", model="not-probed")
    monkeypatch.setattr(
        gateway, "ready", lambda: (_ for _ in ()).throw(AssertionError("readiness probe"))
    )
    app = create_app(settings(), repo, ai_gateway=gateway)
    with TestClient(app) as client:
        response = client.get(CAPS, headers=HEADERS)
        assert response.json()["availability"] == "UNAVAILABLE"
        assert response.headers["x-investigation-unavailable-reason"] == "DISPATCH_UNAVAILABLE"
    repo.close()


def test_worker_command_does_not_report_success_for_undrained_ownership(monkeypatch):
    from types import SimpleNamespace

    from c2hunter_controller import ai_worker

    config = settings().model_copy(
        update={
            "database_url": "postgresql://never-opened",
            "s3_endpoint": "http://127.0.0.1:1",
        }
    )
    monkeypatch.setattr(ai_worker, "Settings", lambda: config)
    monkeypatch.setattr(ai_worker, "MinioBlobStore", lambda *_: object())
    monkeypatch.setattr(ai_worker, "PostgresRepository", lambda *_: object())
    monkeypatch.setattr(
        ai_worker, "create_model_gateway", lambda **_: SimpleNamespace(ready=lambda: True)
    )
    monkeypatch.setattr(ai_worker, "AIAnalysisService", lambda *_: object())
    monkeypatch.setattr(ai_worker, "RedisAIAnalysisWorkerQueue", lambda *_a, **_k: object())
    monkeypatch.setattr(ai_worker, "start_http_server", lambda *_a, **_k: None)
    monkeypatch.setattr(ai_worker.signal, "signal", lambda *_: None)
    monkeypatch.setattr(
        ai_worker,
        "AIAnalysisWorker",
        lambda *_a, **_k: SimpleNamespace(run=lambda _: None, investigation_drained=False),
    )
    monkeypatch.setattr("sys.argv", ["c2hunter-ai-worker"])
    assert ai_worker.main() == 1
