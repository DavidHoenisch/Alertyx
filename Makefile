# Alertyx development tasks
#
# Run `make` or `make help` to list available targets.

BINARY   ?= Alertyx
GO       ?= go
FUZZTIME ?= 30s
COVERAGE ?= coverage.out
GO_DIRS  := $(shell $(GO) list -f '{{.Dir}}' ./...)

.PHONY: help build build-all clean test test-race test-cover cover fmt fmt-check vet lint \
        fuzz mutation ci deps integration integration-matrix deploy-install deploy-uninstall \
        mod tidy

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}'

build: ## Build the Alertyx binary
	$(GO) build -o $(BINARY) .

build-all: ## Compile all packages (CI build check)
	$(GO) build ./...

clean: ## Remove build artifacts
	rm -f $(BINARY) $(COVERAGE) coverage.html

test: ## Run unit tests
	$(GO) test ./...

test-race: ## Run tests with the race detector
	$(GO) test -race ./...

test-cover: ## Run tests with race detection and write coverage profile
	$(GO) test -race -coverprofile=$(COVERAGE) ./...

cover: test-cover ## Generate an HTML coverage report
	$(GO) tool cover -html=$(COVERAGE) -o coverage.html
	@echo "Wrote coverage.html"

fmt: ## Format Go source files
	gofmt -w $(GO_DIRS)

fmt-check: ## Fail if any Go files need formatting
	@test -z "$$(gofmt -l $(GO_DIRS))"

vet: ## Run go vet
	$(GO) vet ./...

lint: fmt-check vet ## Run formatting and vet checks

fuzz: ## Run time-limited fuzz tests (FUZZTIME=$(FUZZTIME))
	FUZZTIME=$(FUZZTIME) ./scripts/fuzz.sh

mutation: ## Run mutation tests on ./techs (requires gremlins)
	./scripts/mutation-test.sh

ci: build-all test-cover fuzz ## Run the main CI pipeline locally

deps: ## Install eBPF build dependencies (Debian/Ubuntu)
	./scripts/install-ebpf-deps.sh

integration: ## Run integration test harness (no live eBPF)
	$(GO) test ./test/integration/...

integration-live: ## Run live eBPF integration tests (requires root)
	sudo $(GO) test -tags=integration -v ./test/integration/...

integration-matrix: ## Run integration tests across Vagrant kernel matrix
	./scripts/test-kernel-matrix.sh

deploy-install: ## Install binary and systemd unit (requires root)
	sudo ./deploy/install.sh

deploy-uninstall: ## Remove installed binary and systemd unit (requires root)
	sudo ./deploy/uninstall.sh

mod: ## Download module dependencies
	$(GO) mod download

tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

.DEFAULT_GOAL := help
