from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest

from .production import PostgresRepository
from .queueing import ControllerQueue
from .repositories import Repository
from .storage import FlowStore


def operations_router(
    repository: Repository,
    flow_store: FlowStore,
    work_queue: ControllerQueue,
    registry: CollectorRegistry,
) -> APIRouter:
    """Build health, readiness, and metrics routes."""
    router = APIRouter(tags=["operations"])

    @router.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/api/v1/ready")
    def ready() -> JSONResponse:
        if isinstance(repository, PostgresRepository):
            dependencies = {
                "postgres": repository.database_ready(),
                "object_storage": repository.blob_store.ready(),
                "clickhouse": flow_store.ready(),
                "redis": work_queue.ready(),
            }
        else:
            dependencies = {
                "repository": repository.ready(),
                "flow_store": flow_store.ready(),
                "queue": work_queue.ready(),
            }
        is_ready = all(dependencies.values())
        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={
                "status": "ready" if is_ready else "not_ready",
                "dependencies": dependencies,
            },
        )

    @router.get("/api/v1/metrics")
    def metrics() -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    return router
