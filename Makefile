GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=greywall
BINARY_UNIX=$(BINARY_NAME)_unix
TUN2SOCKS_VERSION=v2.5.2
TUN2SOCKS_BIN_DIR=internal/sandbox/bin

.PHONY: all build build-ci build-linux test test-ci clean deps install-lint-tools setup setup-ci run fmt lint release release-minor download-tun2socks help

all: build

download-tun2socks:
	@echo "Downloading tun2socks $(TUN2SOCKS_VERSION)..."
	@mkdir -p $(TUN2SOCKS_BIN_DIR)
	@curl -sL "https://github.com/xjasonlyu/tun2socks/releases/download/$(TUN2SOCKS_VERSION)/tun2socks-linux-amd64.zip" -o /tmp/tun2socks-linux-amd64.zip
	@unzip -o -q /tmp/tun2socks-linux-amd64.zip -d /tmp/tun2socks-amd64
	@mv /tmp/tun2socks-amd64/tun2socks-linux-amd64 $(TUN2SOCKS_BIN_DIR)/tun2socks-linux-amd64
	@chmod +x $(TUN2SOCKS_BIN_DIR)/tun2socks-linux-amd64
	@rm -rf /tmp/tun2socks-linux-amd64.zip /tmp/tun2socks-amd64
	@curl -sL "https://github.com/xjasonlyu/tun2socks/releases/download/$(TUN2SOCKS_VERSION)/tun2socks-linux-arm64.zip" -o /tmp/tun2socks-linux-arm64.zip
	@unzip -o -q /tmp/tun2socks-linux-arm64.zip -d /tmp/tun2socks-arm64
	@mv /tmp/tun2socks-arm64/tun2socks-linux-arm64 $(TUN2SOCKS_BIN_DIR)/tun2socks-linux-arm64
	@chmod +x $(TUN2SOCKS_BIN_DIR)/tun2socks-linux-arm64
	@rm -rf /tmp/tun2socks-linux-arm64.zip /tmp/tun2socks-arm64
	@echo "tun2socks binaries downloaded to $(TUN2SOCKS_BIN_DIR)/"

build: download-tun2socks
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/greywall

build-ci: download-tun2socks
	@echo "CI: Building $(BINARY_NAME) with version info..."
	$(eval VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev"))
	$(eval BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ'))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))
	$(GOBUILD) -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)" -o $(BINARY_NAME) -v ./cmd/greywall

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

test-ci:
	@echo "CI: Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f coverage.out
	rm -f $(TUN2SOCKS_BIN_DIR)/tun2socks-linux-*

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

build-linux: download-tun2socks
	@echo "Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./cmd/greywall

build-darwin:
	@echo "Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_NAME)_darwin -v ./cmd/greywall

install-lint-tools:
	@echo "Installing linting tools..."
	go install mvdan.cc/gofumpt@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "Linting tools installed"

setup: deps install-lint-tools
	@echo "Development environment ready"

setup-ci: deps install-lint-tools
	@echo "CI environment ready"

run: build
	./$(BINARY_NAME)

fmt:
	@echo "Formatting code..."
	gofumpt -w .

lint:
	@echo "Linting code..."
	golangci-lint run --allow-parallel-runners

release:
	@echo "Creating patch release..."
	./scripts/release.sh patch

release-minor:
	@echo "Creating minor release..."
	./scripts/release.sh minor

help:
	@echo "Available targets:"
	@echo "  all                - build (default)"
	@echo "  build              - Build the binary (downloads tun2socks if needed)"
	@echo "  build-ci           - Build for CI with version info"
	@echo "  build-linux        - Build for Linux"
	@echo "  build-darwin       - Build for macOS"
	@echo "  download-tun2socks - Download tun2socks binaries for embedding"
	@echo "  test               - Run tests"
	@echo "  test-ci            - Run tests for CI with coverage"
	@echo "  clean              - Clean build artifacts"
	@echo "  deps               - Download dependencies"
	@echo "  install-lint-tools - Install linting tools"
	@echo "  setup              - Setup development environment"
	@echo "  setup-ci           - Setup CI environment"
	@echo "  run                - Build and run"
	@echo "  fmt                - Format code"
	@echo "  lint               - Lint code"
	@echo "  release            - Create patch release (v0.0.X)"
	@echo "  release-minor      - Create minor release (v0.X.0)"
	@echo "  help               - Show this help"
