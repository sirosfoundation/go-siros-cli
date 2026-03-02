# E2E Test Makefile for go-siros-cli

.PHONY: help up down test test-ci clean logs status

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Docker Compose project name
PROJECT_NAME := go-siros-cli-e2e

# Configuration
export WALLET_BACKEND_URL ?= http://localhost:8080
export WEBAUTHN_RP_ID ?= localhost

up: ## Start the test environment
	@echo "Starting test environment..."
	docker compose -p $(PROJECT_NAME) up -d
	@echo "Waiting for services to be ready..."
	@while ! curl -sf $(WALLET_BACKEND_URL)/status >/dev/null 2>&1; do \
		echo "Waiting for wallet-backend..."; \
		sleep 2; \
	done
	@echo "Test environment ready!"

down: ## Stop the test environment
	@echo "Stopping test environment..."
	docker compose -p $(PROJECT_NAME) down -v --remove-orphans

test: up ## Run e2e tests (starts environment if needed)
	@echo "Running e2e tests..."
	cd .. && go test -v -tags=e2e -timeout 5m ./e2e/...

test-fast: ## Run e2e tests without starting environment (assumes already running)
	@echo "Running e2e tests (environment must be running)..."
	cd .. && go test -v -tags=e2e -timeout 5m ./e2e/...

test-ci: ## Run e2e tests for CI (starts, tests, stops)
	@echo "Running CI e2e test suite..."
	$(MAKE) up
	$(MAKE) test-fast || ($(MAKE) down && exit 1)
	$(MAKE) down

test-unit: ## Run unit tests only (no external dependencies)
	@echo "Running unit tests..."
	cd .. && go test -v ./e2e/... -run "TestPRF"

clean: down ## Clean up test environment and artifacts
	@echo "Cleaning up..."
	rm -rf ../test-results/

logs: ## Show logs from test services
	docker compose -p $(PROJECT_NAME) logs -f

status: ## Show status of test services
	docker compose -p $(PROJECT_NAME) ps

# Backend logs only
logs-backend: ## Show wallet-backend logs
	docker compose -p $(PROJECT_NAME) logs -f wallet-backend

# Restart backend only
restart-backend: ## Restart wallet-backend
	docker compose -p $(PROJECT_NAME) restart wallet-backend
