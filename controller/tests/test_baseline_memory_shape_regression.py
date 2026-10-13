"""Strict Memory persisted-envelope admission without programmer-error masking."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_retained_regression import two_documents
from tests.test_historical_source import START, config, stored


@pytest.mark.parametrize("operation", ["get", "page", "preview", "create-replay"])
@pytest.mark.parametrize(
    "mutation",
    [
        "envelope-null",
        "envelope-list",
        "envelope-dict",
        "envelope-short",
        "envelope-long",
        "publication-bool",
        "raw-bytes",
        "raw-null",
        "digest-null",
        "digest-int",
        "size-bool",
        "size-string",
        "key-null",
        "key-int",
        "key-short",
        "key-string",
        "key-long",
        "key-scope-int",
        "key-generation-null",
        "generations-null",
        "generations-list",
        "scopes-null",
        "scopes-list",
    ],
)
def test_memory_stored_shape_admitted_before_decode(
    operation: str, mutation: str, monkeypatch: Any, record_property: Any
) -> None:
    with closing(MemoryRepository()) as repo:
        head, _ = two_documents(repo)
        repo.save_job(stored())
        scopes, generations = repo._baseline_scopes, repo._baseline_generations
        key = (head.config.scope_id, head.active.generation_id)
        env = generations[key]
        changes = {
            "envelope-null": None,
            "envelope-list": list(env),
            "envelope-dict": dict(enumerate(env)),
            "envelope-short": env[:3],
            "envelope-long": (*env, 1),
            "publication-bool": (True, *env[1:]),
            "raw-bytes": (env[0], env[1].encode(), *env[2:]),
            "raw-null": (env[0], None, *env[2:]),
            "digest-null": (*env[:2], None, env[3]),
            "digest-int": (*env[:2], 1, env[3]),
            "size-bool": (*env[:3], True),
            "size-string": (*env[:3], str(env[3])),
        }
        keys = {
            "key-null": None,
            "key-int": 1,
            "key-short": (key[0],),
            "key-string": key[0],
            "key-long": (*key, 1),
            "key-scope-int": (1, key[1]),
            "key-generation-null": (key[0], None),
        }
        if mutation in changes:
            repo._baseline_generations = dict(generations, **{})
            repo._baseline_generations[key] = changes[mutation]
        elif mutation in keys:
            repo._baseline_generations = {**generations, keys[mutation]: env}
        elif mutation.startswith("generations"):
            repo._baseline_generations = None if mutation.endswith("null") else []
        else:
            repo._baseline_scopes = None if mutation.endswith("null") else []
        before = repr((repo._baseline_scopes, repo._baseline_generations))
        calls = []
        original = bs.g.decode_generation

        def decode(*args: Any, **kw: Any) -> Any:
            calls.append(1)
            return original(*args, **kw)

        monkeypatch.setattr(bs.g, "decode_generation", decode)
        operations = {
            "get": lambda: repo.get_baseline_scope(head.config.scope_id),
            "page": repo.page_baseline_scopes,
            "preview": lambda: repo.preview_baseline_source(
                head.config.scope_id, "root", 2, "APPROVAL"
            ),
            "create-replay": lambda: repo.create_baseline_scope(config(), "fixture-admin", START),
        }
        caught = None
        try:
            operations[operation]()
        except Exception as exc:
            caught = exc
        assert before == repr((repo._baseline_scopes, repo._baseline_generations))
        record_property("actual_exception", type(caught).__name__)
        record_property("decode_calls_before_rejection", len(calls))
        assert calls == []
        repo._baseline_scopes, repo._baseline_generations = scopes, generations
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(repo.get_baseline_scope, head.config.scope_id).result(10) == head
        assert isinstance(caught, bs.BaselineStorageError), repr(caught)
        assert caught.code == "BASELINE_STORAGE_UNAVAILABLE"


def test_memory_programmer_typeerror_not_masked(monkeypatch: Any) -> None:
    with closing(MemoryRepository()) as repo:
        head, _ = two_documents(repo)
        error = TypeError("owned programmer failure")
        calls = []

        def fail(*_a: Any, **_kw: Any) -> Any:
            calls.append(1)
            raise error

        monkeypatch.setattr(bs.g, "decode_generation", fail)
        with pytest.raises(TypeError) as caught:
            repo.get_baseline_scope(head.config.scope_id)
        assert caught.value is error and calls == [1]
