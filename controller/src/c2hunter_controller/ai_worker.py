from __future__ import annotations

import argparse
import json
import os
import signal
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from time import perf_counter
from typing import Any, Protocol

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, start_http_server

from .ai_analysis import AIAnalysisService
from .ai_gateway import create_model_gateway
from .ai_queueing import RedisAIAnalysisWorkerQueue
from .config import Settings
from .production import MinioBlobStore, PostgresRepository


class WorkerQueue(Protocol):
    def claim(self, timeout: int = 1) -> dict[str, str] | None: ...

    def ack(self, receipt: str) -> None: ...

    def recover(self) -> int: ...

    def depth(self) -> tuple[int, int]: ...


class AIWorkerMetrics:
    def __init__(self, *, provider: str, model: str) -> None:
        self.provider = provider
        self.model = model
        self.registry = CollectorRegistry()
        self.inference_duration = Histogram(
            "c2hunter_ai_inference_duration_seconds",
            "AI worker Run execution duration",
            ["provider", "model", "status"],
            buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
            registry=self.registry,
        )
        self.failures = Counter(
            "c2hunter_ai_failures_total",
            "AI worker Run failures",
            ["reason"],
            registry=self.registry,
        )
        self.schema_invalid = Counter(
            "c2hunter_ai_schema_invalid_total",
            "AI outputs rejected by schema or evidence validation",
            registry=self.registry,
        )
        self.waiting_depth = Gauge(
            "c2hunter_ai_queue_waiting_depth",
            "AI Runs waiting in the worker queue",
            registry=self.registry,
        )
        self.processing_depth = Gauge(
            "c2hunter_ai_queue_processing_depth",
            "AI Runs claimed and awaiting acknowledgement",
            registry=self.registry,
        )

    @staticmethod
    def _safe(operation: Callable[[], None]) -> None:
        try:
            operation()
        except Exception:
            # Telemetry must never alter Run state or queue acknowledgement.
            pass

    def observe_execution(self, duration: float, run: dict[str, Any]) -> None:
        status = str(run.get("status") or "UNKNOWN")
        error_code = str(run.get("error_code") or "AI_ANALYSIS_FAILED")
        self._safe(
            lambda: self.inference_duration.labels(
                provider=self.provider, model=self.model, status=status
            ).observe(duration)
        )
        if status == "FAILED":
            self._safe(lambda: self.failures.labels(reason=error_code).inc())
            if error_code == "MODEL_OUTPUT_INVALID":
                self._safe(self.schema_invalid.inc)

    def observe_exception(self, duration: float, exc: Exception) -> None:
        self._safe(
            lambda: self.inference_duration.labels(
                provider=self.provider, model=self.model, status="EXCEPTION"
            ).observe(duration)
        )
        self._safe(lambda: self.failures.labels(reason=type(exc).__name__).inc())

    def set_queue_depth(self, waiting: int, processing: int) -> None:
        self._safe(lambda: self.waiting_depth.set(waiting))
        self._safe(lambda: self.processing_depth.set(processing))


class AIAnalysisWorker:
    def __init__(
        self,
        queue: WorkerQueue,
        service: AIAnalysisService,
        *,
        health_path: Path | None = None,
        metrics: AIWorkerMetrics | None = None,
    ) -> None:
        self.queue = queue
        self.service = service
        self.health_path = health_path
        gateway = getattr(service, "gateway", None)
        self.metrics = metrics or AIWorkerMetrics(
            provider=str(getattr(gateway, "provider", "unknown")),
            model=str(getattr(gateway, "model", "unknown")),
        )
        self.processed_runs = 0
        self.last_error: str | None = None

    def run_once(self, timeout: int = 1) -> bool:
        self._update_queue_depth()
        message = self.queue.claim(timeout)
        if message is None:
            self._write_health("RUNNING")
            return False
        self._update_queue_depth()
        receipt = message.get("receipt", "")
        started = perf_counter()
        try:
            if not receipt:
                raise ValueError("AI queue receipt is required")
            run = self.service.execute(message["ai_run_id"])
            self.metrics.observe_execution(perf_counter() - started, run)
            self.queue.ack(receipt)
            self.processed_runs += 1
            self.last_error = None
            self._write_health("RUNNING")
            return True
        except Exception as exc:
            self.metrics.observe_exception(perf_counter() - started, exc)
            self.last_error = str(exc)
            self._write_health("DEGRADED")
            return False
        finally:
            self._update_queue_depth()

    def run(self, stopped: Event) -> None:
        self._write_health("RUNNING")
        while not stopped.is_set():
            self.run_once(timeout=1)
        self._write_health("STOPPED")

    def _update_queue_depth(self) -> None:
        try:
            waiting, processing = self.queue.depth()
        except Exception:
            return
        self.metrics.set_queue_depth(waiting, processing)

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
    gateway = create_model_gateway(
        provider=settings.ai_model_provider,
        base_url=settings.ai_model_base_url,
        model=settings.ai_model_name,
        api_key=settings.ai_model_api_key.get_secret_value(),
        timeout_seconds=settings.ai_model_timeout_seconds,
        retries=settings.ai_model_retries,
        temperature=settings.ai_model_temperature,
        context_tokens=settings.ai_model_context_tokens,
        max_output_tokens=settings.ai_model_max_output_tokens,
    )
    if not gateway.ready():
        raise RuntimeError(
            f"AI model is not ready: provider={settings.ai_model_provider} "
            f"model={settings.ai_model_name}"
        )
    service = AIAnalysisService(repository, gateway)
    queue = RedisAIAnalysisWorkerQueue(
        settings.redis_url,
        visibility_timeout=settings.queue_visibility_timeout_seconds,
    )
    metrics = AIWorkerMetrics(
        provider=settings.ai_model_provider,
        model=settings.ai_model_name,
    )
    start_http_server(settings.ai_metrics_port, registry=metrics.registry)
    stopped = Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    AIAnalysisWorker(queue, service, health_path=health_path, metrics=metrics).run(stopped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
