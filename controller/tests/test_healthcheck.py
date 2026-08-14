import runpy
import urllib.request
from types import SimpleNamespace

import pytest

from c2hunter_controller import healthcheck


class Response:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_healthcheck_accepts_healthy_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    request = SimpleNamespace(url=None, timeout=None)

    def open_health(url: str, timeout: int) -> Response:
        request.url = url
        request.timeout = timeout
        return Response(200)

    monkeypatch.setattr(healthcheck, "urlopen", open_health)

    healthcheck.main()

    assert request.url == "http://127.0.0.1:8000/api/v1/health"
    assert request.timeout == 3


def test_healthcheck_rejects_unhealthy_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(healthcheck, "urlopen", lambda *_args, **_kwargs: Response(503))

    with pytest.raises(SystemExit) as exc_info:
        healthcheck.main()

    assert exc_info.value.code == 1


def test_healthcheck_module_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_args, **_kwargs: Response(200))

    runpy.run_module("c2hunter_controller.healthcheck", run_name="__main__")
