# Runs the Go/Python/Rust AWP triangle demo (trip-planner.local,
# concierge.local, activities.local — see each subdirectory's README.md).
#
# Native (3 terminals, fastest iteration):
#   make env && make run-go   (then, in two more terminals) make run-python / make run-rust
#
# Docker (1 command, no local toolchains needed):
#   make docker-env && make docker-up

.PHONY: help env build build-go build-python build-rust \
        run-go run-python run-rust \
        test test-go test-python test-rust \
        docker-env docker-build docker-up docker-down docker-restart docker-logs \
        clean

help:
	@echo "Native : make env                     # copy each agent's .env.example -> .env"
	@echo "         make build                   # build all three"
	@echo "         make run-go / run-python / run-rust   # one per terminal"
	@echo "         make test                    # run all three test suites"
	@echo "Docker : make docker-env               # copy agents/.env.example -> agents/.env"
	@echo "         make docker-up                # build + start the triangle"
	@echo "         make docker-logs / docker-down"

## Copies each agent's .env.example -> .env if missing. Fill in
## XAI_API_KEY (https://console.x.ai/) in all three afterward.
env:
	@for d in go python rust; do \
		if [ ! -f $$d/.env ]; then cp $$d/.env.example $$d/.env; echo "created $$d/.env — fill in XAI_API_KEY"; fi; \
	done

build: build-go build-python build-rust

build-go:
	cd go && go build -o /tmp/trip-planner .

build-python:
	cd python && uv sync

build-rust:
	cd rust && cargo build

## Each run-* target must run from its own directory: every agent loads
## .env relative to its current working directory (see each README.md).
run-go:
	cd go && go run .

run-python:
	cd python && uv run python -m concierge.main

run-rust:
	cd rust && cargo run

test: test-go test-python test-rust

test-go:
	cd go && go test ./...

test-python:
	cd python && uv run pytest

test-rust:
	cd rust && cargo test

## Copies agents/.env.example -> agents/.env if missing — this is the one
## docker compose itself reads for variable substitution, separate from
## each agent's own .env used for native runs.
docker-env:
	@if [ ! -f .env ]; then cp .env.example .env; echo "created agents/.env — fill in XAI_API_KEY"; fi

docker-build:
	docker compose build

docker-up:
	docker compose up --build

docker-down:
	docker compose down

docker-restart: docker-down docker-up

docker-logs:
	docker compose logs -f

clean:
	rm -rf rust/target python/__pycache__ python/.pytest_cache python/**/__pycache__
