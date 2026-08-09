from __future__ import annotations

import argparse
import json
import os
import signal
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Protocol

from .ai_analysis import AIAnalysisService, FakeGateway
from .ai_queueing import RedisAIAnalysisWorkerQueue
from .config import Settings
from .production import MinioBlobStore, PostgresRepository


class WorkerQueue(Protocol):
    def claim(self, timeout: int = 1) -> dict[str, str] | None: ...

    def ack(self, receipt: str) -> None: ...

    def recover(self) -> int: ...


class AIAnalysisWorker:
    def __init__(
        self,
        queue: WorkerQueue,
        service: AIAnalysisService,
        *,
        health_path: Path | None = None,
    ) -> None:
        self.queue = queue
        self.service = service
        self.health_path = health_path
        self.processed_runs = 0
        self.last_error: str | None = None

    def run_once(self, timeout: int = 1) -> bool:
        message = self.queue.claim(timeout)
        if message is None:
            self._write_health("RUNNING")
            return False
        receipt = message.get("receipt", "")
        try:
            if not receipt:
                raise ValueError("AI queue receipt is required")
            self.service.execute(message["ai_run_id"])
            self.queue.ack(receipt)
            self.processed_runs += 1
            self.last_error = None
            self._write_health("RUNNING")
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self._write_health("DEGRADED")
            return False

    def run(self, stopped: Event) -> None:
        self._write_health("RUNNING")
        while not stopped.is_set():
            self.run_once(timeout=1)
        self._write_health("STOPPED")

    def _write_health(self, status: str) -> None:
        if self.health_path is None:
            return
        payload = {
            "status": status,
            "pid": os.getpid(),
            "updated_at": datetime.now(UTC).isoformat(),
            "processed_runs": self.processed_runs,
            "last_error": self.last_error,
        }
        self.health_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=self.health_path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
            os.replace(temporary, self.health_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def _healthy(path: Path, max_age: int) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        updated_at = datetime.fromisoformat(payload["updated_at"])
        age = (datetime.now(UTC) - updated_at).total_seconds()
        return payload.get("status") in {"RUNNING", "DEGRADED"} and age <= max_age
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(prog="c2hunter-ai-worker")
    parser.add_argument("command", nargs="?", default="run", choices=("run", "healthcheck"))
    parser.add_argument("--max-age", type=int, default=30)
    args = parser.parse_args()
    health_path = Path(
        os.getenv("C2HUNTER_AI_WORKER_HEALTH_FILE", "/tmp/c2hunter-ai-worker-health.json")
    )
    if args.command == "healthcheck":
        return 0 if _healthy(health_path, args.max_age) else 1

    settings = Settings()
    if not settings.database_url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("AI worker requires PostgreSQL")
    if settings.s3_endpoint == "memory://":
        raise RuntimeError("AI worker requires configured MinIO/S3 storage")
    repository = PostgresRepository(
        settings.database_url,
        MinioBlobStore(
            settings.s3_endpoint,
            settings.s3_access_key,
            settings.s3_secret_key,
            settings.s3_bucket,
        ),
    )
    service = AIAnalysisService(repository, FakeGateway())
    queue = RedisAIAnalysisWorkerQueue(
        settings.redis_url,
        visibility_timeout=settings.queue_visibility_timeout_seconds,
    )
    stopped = Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    AIAnalysisWorker(queue, service, health_path=health_path).run(stopped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
