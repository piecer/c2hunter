SHELL := /bin/bash
PYTHON ?= python3.12
VENV := .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
COMPOSE := docker compose --env-file .env

.PHONY: setup lint test test-unit test-integration test-e2e build sensor-agent up down generate-test-pcaps benchmark-1m clean

setup:
	@test -f .env || cp .env.example .env
	@mkdir -p artifacts testdata/generated
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip==25.1.1
	$(PIP) install -r requirements.lock
	$(PIP) install --no-deps -e ./controller -e ./analysis
	npm --prefix web ci --ignore-scripts

build:
	$(VENV)/bin/python -m compileall -q controller/src analysis/src
	cd sensor && go build ./...
	npm --prefix web run build
	$(MAKE) sensor-agent
	$(COMPOSE) build

sensor-agent:
	VERSION="$${VERSION:-dev}" COMMIT="$${COMMIT:-$$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}" scripts/build-sensor-tarball.sh

up:
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down --remove-orphans

lint:
	@test -z "$$(gofmt -l sensor)" || { gofmt -l sensor; exit 1; }
	cd sensor && go vet ./...
	$(RUFF) check controller analysis tools
	$(RUFF) format --check controller analysis tools
	$(MYPY) controller/src analysis/src
	npm --prefix web run lint

test: test-unit test-integration

test-unit:
	cd sensor && go test ./...
	$(PYTEST) -q controller/tests analysis/tests
	PYTHONPATH=sensor/worker/src $(PYTEST) -q sensor/worker/tests
	python3 tools/traffic-generator/test_generate.py
	python3 tools/benchmark/test_benchmark.py
	npm --prefix web run test

test-integration:
	$(PYTEST) -q controller/tests analysis/tests -m "not e2e"
	python3 tools/traffic-generator/generate.py --output testdata/generated

test-e2e:
	npm --prefix web exec playwright install chromium
	npm --prefix web run test:e2e

generate-test-pcaps:
	python3 tools/traffic-generator/generate.py --output testdata/generated --seed 20260720

benchmark-1m:
	python3 tools/benchmark/benchmark.py --packets 1000000 --chunk-size 10000 --output artifacts --seed 20260720

clean:
	rm -rf web/dist web/coverage web/test-results artifacts/web-coverage artifacts/playwright-report testdata/generated/*
	find controller analysis tools -type d \( -name __pycache__ -o -name .pytest_cache \) -prune -exec rm -rf {} +
	find controller analysis tools -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
