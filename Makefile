.PHONY: build build-native test clean install lint fmt

BINARY_NAME=wallet-cli
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X github.com/sirosfoundation/go-siros-cli/internal/version.Version=$(VERSION) -X github.com/sirosfoundation/go-siros-cli/internal/version.BuildTime=$(BUILD_TIME)"

# Default target
all: build

# Build the binary
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/wallet-cli

# Build with native libfido2 support (requires libfido2-dev)
build-native:
	go build -tags libfido2 $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/wallet-cli

# Build for all platforms
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/wallet-cli
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/wallet-cli
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/wallet-cli
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/wallet-cli
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/wallet-cli

# Install to GOPATH/bin
install: build
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint the code
lint:
	golangci-lint run ./...

# Format the code
fmt:
	go fmt ./...
	goimports -w .

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	go mod download
	go mod tidy

# Generate mocks (if needed)
generate:
	go generate ./...

# Run the CLI in development
run:
	go run ./cmd/wallet-cli $(ARGS)

# Development helpers
dev-register:
	go run ./cmd/wallet-cli auth register --display-name "Dev Wallet"

dev-login:
	go run ./cmd/wallet-cli auth login

dev-list:
	go run ./cmd/wallet-cli credentials list
