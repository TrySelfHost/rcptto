# rcpttō — developer Makefile
# Common targets for building, testing, and quality gates.

MODULE      := github.com/tryselfhost/rcptto
GO          ?= go
GOFLAGS     ?=
BIN_DIR     := bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## Sync go.mod/go.sum
	$(GO) mod tidy

.PHONY: fmt
fmt: ## Format code
	gofmt -w .
	$(GO) run golang.org/x/tools/cmd/goimports@latest -w -local $(MODULE) . 2>/dev/null || true

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint (install: https://golangci-lint.run)
	golangci-lint run

.PHONY: test
test: ## Run unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Test with coverage report
	$(GO) test -race -covermode=atomic -coverprofile=coverage.txt ./...
	$(GO) tool cover -func=coverage.txt | tail -1

.PHONY: build
build: ## Build all binaries into ./bin
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/ ./...

.PHONY: check
check: fmt vet test ## Fast local pre-commit gate

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) dist coverage.txt coverage.html
