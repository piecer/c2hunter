from __future__ import annotations

import argparse
import os
import signal
from pathlib import Path
from threading import Event

from .analysis import execute_analysis
from .health import check_health
from .queue import RedisQueue
from .runtime import Worker


def main() -> int:
    parser = argparse.ArgumentParser(prog="c2hunter-worker")
    parser.add_argument("command", nargs="?", default="run", choices=("run", "healthcheck"))
    parser.add_argument("--max-age", type=int, default=30)
    args = parser.parse_args()
    health_path = Path(os.getenv("C2HUNTER_WORKER_HEALTH_FILE", "/tmp/c2hunter-worker-health.json"))
    if args.command == "healthcheck":
        return 0 if check_health(health_path, max_age_seconds=args.max_age) else 1

    stopped = Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    queue = RedisQueue(os.getenv("C2HUNTER_REDIS_URL", "redis://redis:6379/0"))
    Worker(queue=queue, execute=execute_analysis, health_path=health_path).run(stopped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
