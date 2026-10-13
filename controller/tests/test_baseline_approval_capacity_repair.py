"""Exact generation storage byte gate through the real public page method."""

import hashlib
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_approval_oracle_repair import canonical
from tests.test_baseline_approval_oracle_repair import repo as repo_fixture
from tests.test_baseline_approval_retention import publish
from tests.test_historical_generation_bounds import capacity_document
from tests.test_historical_source import START, config

repo = repo_fixture


@pytest.mark.parametrize("extra", [0, 1])
def test_public_generation_exact_bytes(repo: Any, monkeypatch: Any, extra: int) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    _, first = publish(repo, 0)
    if isinstance(repo, MemoryRepository):
        envelope = repo._baseline_generations[(config().scope_id, first.receipt.generation_id)]
    else:
        envelope = repo.connection.execute(
            "SELECT publication_revision,document_json,content_sha256,byte_size "
            "FROM baseline_generations"
        ).fetchone()
    original = g.GenerationDocument.model_validate_json(envelope[1])
    cfg_data = config().to_mapping()
    cfg_data["sensor_key"] = "S" * 200
    cfg_data["hosts"][0]["epoch"] = "界" * 64
    cfg = h.ScopeConfig.from_mapping(cfg_data)
    value = capacity_document(original, 2097152)
    value["scope_config_sha256"] = h.scope_config_sha256(cfg)
    for window in value["windows"]:
        window["key"]["scope_config_sha256"] = value["scope_config_sha256"]
    raw = canonical(value)
    assert len(raw.encode()) == 2097152
    document = g.decode_generation(
        raw, content_sha256=hashlib.sha256(raw.encode()).hexdigest(), byte_size=2097152, scope=cfg
    )
    view = g.ScopeView(
        config=cfg,
        config_sha256=value["scope_config_sha256"],
        control_revision=16,
        frozen=False,
        state="HAS_REFERENCE",
        accepted_event_end=document.sources[-1].event_end,
        active=g.generation_view(document),
        previous=None,
        created_by="admin",
        created_at=START,
    )
    if extra:
        value["sources"][-1]["reason"] += "x"
        raw = canonical(value)
    assert len(raw.encode()) == 2097152 + extra
    digest = hashlib.sha256(raw.encode()).hexdigest()
    if isinstance(repo, MemoryRepository):
        repo._baseline_scopes[config().scope_id] = view
        repo._baseline_generations[(config().scope_id, first.receipt.generation_id)] = (
            16,
            raw,
            digest,
            2097152,
        )
    else:
        cfg_raw = canonical(cfg.to_mapping())
        repo.connection.execute("PRAGMA ignore_check_constraints=ON")
        repo.connection.execute(
            "UPDATE baseline_scopes SET config_json=?,config_byte_size=?,"
            "config_content_sha256=?,config_sha256=?,control_revision=16,accepted_event_end=?",
            (
                cfg_raw,
                len(cfg_raw.encode()),
                hashlib.sha256(cfg_raw.encode()).hexdigest(),
                view.config_sha256,
                view.to_mapping()["accepted_event_end"],
            ),
        )
        repo.connection.execute(
            "UPDATE baseline_generations SET publication_revision=16,document_json=?,"
            "content_sha256=?,byte_size=2097152",
            (raw, digest),
        )
        repo.connection.commit()
    decode = g.GenerationDocument.model_validate_json
    decodes = []

    def observed(*args: Any, **kw: Any) -> Any:
        decodes.append(True)
        return decode(*args, **kw)

    monkeypatch.setattr(g.GenerationDocument, "model_validate_json", observed)
    if extra:
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.page_baseline_sources(config().scope_id, first.receipt.generation_id)
        assert decodes == []
    else:
        page = repo.page_baseline_sources(config().scope_id, first.receipt.generation_id)
        assert page.total == 16 and page.items == document.sources
        assert decodes
