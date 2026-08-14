SHELL := /bin/bash
PYTHON ?= python3.12
VENV := .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
GOSEC_VERSION := v2.22.10
SENSOR_COVERAGE_MIN := 69.0
SENSOR_CORE_COVERAGE_MIN := 80.0
SENSOR_CORE_PACKAGES := ./internal/direction ./internal/flow ./internal/capture ./internal/metadata ./internal/packet ./internal/spool ./internal/batch ./internal/flowbatch
COMPOSE := docker compose --env-file .env

.PHONY: setup lint lint-security test test-unit test-integration test-coverage test-e2e test-ai evaluate-ai benchmark-ai backtest-high-volume build sensor-agent up down generate-test-pcaps benchmark-1m clean

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
	$(VENV)/bin/python tools/check_tracked_elf.py
	@test -z "$$(gofmt -l sensor)" || { gofmt -l sensor; exit 1; }
	cd sensor && go vet ./...
	$(RUFF) check controller analysis tools
	$(RUFF) format --check controller analysis tools
	$(MYPY) controller/src analysis/src
	npm --prefix web run lint
	$(MAKE) lint-security

lint-security:
	# Every security rule is enforced; reviewed false positives carry line-specific rationale.
	$(RUFF) check controller/src analysis/src tools --select S
	cd sensor && go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) ./...

test: test-unit test-integration

test-unit:
	cd sensor && go test ./...
	$(PYTEST) -q controller/tests analysis/tests
	PYTHONPATH=sensor/worker/src $(PYTEST) -q sensor/worker/tests
	$(VENV)/bin/python tools/traffic-generator/test_generate.py
	$(VENV)/bin/python tools/benchmark/test_benchmark.py
	npm --prefix web run test

test-integration:
	$(PYTEST) -q controller/tests analysis/tests -m "not e2e"
	$(VENV)/bin/python tools/traffic-generator/generate.py --output testdata/generated

test-coverage:
	# Ratchet current package baselines separately so aggregate coverage cannot hide a regression.
	$(PYTEST) -q controller/tests --cov=c2hunter_controller --cov-report=term --cov-fail-under=80
	$(PYTEST) -q analysis/tests --cov=c2hunter_analysis --cov-report=term --cov-fail-under=86
	$(PYTEST) -q analysis/tests --cov=c2hunter_analysis.detectors --cov-report=term --cov-fail-under=90
	cd sensor && go test -coverprofile=/tmp/c2hunter-sensor-coverage.out ./...
	@actual="$$(cd sensor && go tool cover -func=/tmp/c2hunter-sensor-coverage.out | awk '/^total:/ { gsub("%", "", $$3); print $$3 }')"; \
	$(PYTHON) -c 'import sys; actual = float(sys.argv[1]); minimum = float(sys.argv[2]); print(f"Sensor coverage: {actual:.1f}% (minimum {minimum:.1f}%)"); raise SystemExit(actual < minimum)' "$$actual" "$(SENSOR_COVERAGE_MIN)"
	cd sensor && go test -coverprofile=/tmp/c2hunter-sensor-core-coverage.out $(SENSOR_CORE_PACKAGES)
	@actual="$$(cd sensor && go tool cover -func=/tmp/c2hunter-sensor-core-coverage.out | awk '/^total:/ { gsub("%", "", $$3); print $$3 }')"; \
	$(PYTHON) -c 'import sys; actual = float(sys.argv[1]); minimum = float(sys.argv[2]); print(f"Sensor core coverage: {actual:.1f}% (minimum {minimum:.1f}%)"); raise SystemExit(actual < minimum)' "$$actual" "$(SENSOR_CORE_COVERAGE_MIN)"

test-e2e:
	npm --prefix web exec playwright install chromium
	npm --prefix web run test:e2e

test-ai:
	$(PYTEST) -q controller/tests/test_ai_*.py

evaluate-ai:
	$(VENV)/bin/python -m c2hunter_controller.ai_evaluation evaluate \
		--json artifacts/ai-evaluation-report.json \
		--markdown artifacts/ai-evaluation-report.md

benchmark-ai:
	$(VENV)/bin/python -m c2hunter_controller.ai_evaluation benchmark \
		--json artifacts/ai-benchmark-report.json --iterations 100

backtest-high-volume:
	$(VENV)/bin/python -m c2hunter_analysis.high_volume_backtest \
		--cases analysis/tests/fixtures/high_volume_policy_cases.json \
		--json artifacts/high-volume-policy-backtest.json \
		--markdown artifacts/high-volume-policy-backtest.md

generate-test-pcaps:
	$(VENV)/bin/python tools/traffic-generator/generate.py --output testdata/generated --seed 20260720

benchmark-1m:
	$(VENV)/bin/python tools/benchmark/benchmark.py --packets 1000000 --chunk-size 10000 --output artifacts --seed 20260720

clean:
	rm -rf web/dist web/coverage web/test-results artifacts/web-coverage artifacts/playwright-report testdata/generated/*
	find controller analysis tools -type d \( -name __pycache__ -o -name .pytest_cache \) -prune -exec rm -rf {} +
	find controller analysis tools -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
