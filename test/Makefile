# test/Makefile - Build targets for ingress-node-firewall extended tests

SHELL := /bin/bash

# Binary name
BINARY_NAME := ingress-node-firewall-tests

# Build directory
BUILD_DIR := bin
BINARY_PATH := $(BUILD_DIR)/$(BINARY_NAME)

# Go build flags
GO := go
GOFLAGS ?=
LDFLAGS := -w -s


.PHONY: all
all: build-e2e-tests

.PHONY: build-e2e-tests
build-e2e-tests: ## Build the extended e2e test binary (static, ART compliant)
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	cd ote && $(GO) mod vendor
	cd ote && CGO_ENABLED=0 GO_COMPLIANCE_POLICY="exempt_all" $(GO) build \
		-a -mod=vendor \
		-ldflags "$(LDFLAGS)" \
		-o ../$(BINARY_PATH) ./cmd/main.go
	@echo "Built $(BINARY_PATH)"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning test build artifacts..."
	@rm -rf $(BUILD_DIR)

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
