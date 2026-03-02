.PHONY: build build-native test test-coverage clean install lint fmt check \
        e2e e2e-fast e2e-up e2e-down e2e-logs \
        pre-commit-install pre-commit-run verify help \
        proto proto-install deb deb-clean

BINARY_NAME=wallet-cli
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X github.com/sirosfoundation/go-siros-cli/internal/version.Version=$(VERSION) -X github.com/sirosfoundation/go-siros-cli/internal/version.BuildTime=$(BUILD_TIME)"

# Default target
all: build

# Show help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Build the binary
build: ## Build the wallet-cli binary
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/wallet-cli

# Build with native libfido2 support (requires libfido2-dev)
build-native: ## Build with native libfido2 support
	@go build -tags libfido2 $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/wallet-cli

# Build for all platforms
build-all: ## Build for all platforms
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/wallet-cli
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/wallet-cli
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/wallet-cli
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/wallet-cli
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/wallet-cli

# Install to GOPATH/bin
install: build ## Install to GOPATH/bin
	@cp bin/$(BINARY_NAME) $(GOPATH)/bin/

# Run tests
test: ## Run tests with race detection (skips interactive tests)
	@go test -v -race -short ./...

# Run all tests including interactive ones
test-all: ## Run all tests including interactive pinentry tests
	@go test -v -race ./...

# Run tests with coverage
test-coverage: ## Run tests with coverage report
	@go test -v -race -short -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

# E2E tests with software FIDO2 token
e2e: ## Run e2e tests (starts docker environment)
	$(MAKE) -C e2e test

# E2E tests without docker (assumes backend is running)
e2e-fast: ## Run e2e tests (assumes backend already running)
	$(MAKE) -C e2e test-fast

# Start e2e test environment
e2e-up: ## Start e2e test environment
	$(MAKE) -C e2e up

# Stop e2e test environment
e2e-down: ## Stop e2e test environment
	$(MAKE) -C e2e down

# View e2e environment logs
e2e-logs: ## View e2e test environment logs
	$(MAKE) -C e2e logs

# Lint the code
lint: ## Run golangci-lint
	@golangci-lint run ./...

# Format the code
fmt: ## Format code with gofmt and goimports
	@go fmt ./...
	@goimports -w -local github.com/sirosfoundation/go-siros-cli .

# Check all (CI pipeline)
check: fmt lint test ## Run all checks (format, lint, test)

# Setup pre-commit hooks
pre-commit-install: ## Install pre-commit hooks
	@which pre-commit > /dev/null || (echo "Installing pre-commit..." && pip install pre-commit)
	@pre-commit install
	@echo "Pre-commit hooks installed"

# Run pre-commit on all files
pre-commit-run: ## Run pre-commit on all files
	@pre-commit run --all-files

# Verify code is ready to commit
verify: fmt ## Verify code is properly formatted and passes lint
	@golangci-lint run ./...
	@go build ./...
	@echo "Code verified and ready to commit"

# Clean build artifacts
clean: ## Clean build artifacts
	@rm -rf bin/
	@rm -f coverage.out coverage.html

# Download dependencies
deps: ## Download and tidy dependencies
	@go mod download
	@go mod tidy

# Generate mocks (if needed)
generate: ## Generate mocks and code
	@go generate ./...

# Install protobuf tools
proto-install: ## Install protoc-gen-go and protoc-gen-go-grpc
	@echo "Installing protobuf Go plugins..."
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Done. Make sure $(shell go env GOPATH)/bin is in your PATH"
	@echo "Also requires: protoc (apt install protobuf-compiler or brew install protobuf)"

# Generate protobuf code
proto: ## Generate gRPC code from proto files
	@command -v protoc-gen-go >/dev/null 2>&1 || { echo "Run 'make proto-install' first"; exit 1; }
	@echo "Generating gRPC code..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/daemon/v1/wallet.proto
	@echo "Generated: api/proto/daemon/v1/wallet.pb.go"
	@echo "Generated: api/proto/daemon/v1/wallet_grpc.pb.go"

# Run the CLI in development
run: ## Run the CLI (use ARGS= for arguments)
	@go run ./cmd/wallet-cli $(ARGS)

# Development helpers
dev-register: ## Register a dev wallet
	@go run ./cmd/wallet-cli auth register --display-name "Dev Wallet"

dev-login: ## Login with dev wallet
	@go run ./cmd/wallet-cli auth login

dev-list: ## List dev wallet credentials
	@go run ./cmd/wallet-cli credentials list

# Build Debian package
deb: ## Build Debian package
	@dpkg-buildpackage -us -uc -b

# Clean Debian build artifacts
deb-clean: ## Clean Debian build artifacts
	@debian/rules clean
	@rm -f ../wallet-cli_*.deb ../wallet-cli_*.buildinfo ../wallet-cli_*.changes
