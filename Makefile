# Copyright 2025 CIQ, Inc. All rights reserved.
# Build the plugin

# Default to the latetst vendored schema; allow override to point to fuzzball instance
SPEC_URL ?= __none__
SPEC_FILE ?= $(shell ls code-generation/schemas/fuzzball-v*-openapi.json | sort -V | tail -1)

# Check for required tools
ifeq ($(shell command -v jq 2>/dev/null),)
  $(error "jq is required but not installed. Please install jq to continue.")
endif

ifneq ($(SPEC_URL),__none__)
  ifeq ($(shell command -v curl 2>/dev/null),)
    $(error "curl is required but not installed. Please install curl to continue.")
  endif
  SPEC := $(SPEC_URL)
  VERSION_URL := $(patsubst %/schema,%/version,$(SPEC_URL))
  FB_VERSION_FULL := $(shell curl -fsS --connect-timeout 5 --max-time 30 "$(VERSION_URL)" | jq -r '.version // ""')
  ifeq ($(FB_VERSION_FULL),)
    $(error Could not fetch Fuzzball version from $(VERSION_URL) — check URL/network, or unset SPEC_URL to build from the vendored schema)
  endif
  BASEPATH := $(shell curl -fsS --connect-timeout 5 --max-time 30 "$(SPEC_URL)" | jq -r '.basePath // ""')
  GRADLEW_PROPS := -PopenapiUrl=$(SPEC)
else
  SPEC := $(SPEC_FILE)
  FB_VERSION_FULL := $(shell basename "${SPEC_FILE}" | sed -E 's/fuzzball-(v[^-]+)-openapi.json/\1/')
  BASEPATH := $(shell jq -r '.basePath' "$(SPEC_FILE)")
  GRADLEW_PROPS := -PopenapiFile=$(SPEC)
endif

FB_VERSION := $(shell echo "$(FB_VERSION_FULL)" | sed -E 's/^(v[0-9]+\.[0-9]+).*/\1/')
ifeq ($(FB_VERSION),)
  $(error "Unable to detect fuzzball version from URL or filename")
endif

VERSION := $(shell ./gradlew properties | awk '/^version:/{print $$2}')
$(info SPEC:           $(SPEC))
$(info FB VERSION:     $(FB_VERSION))
$(info PLUGIN VERSION: $(VERSION))
$(info BASEPATH:       $(BASEPATH))

.PHONY: help assemble clean test install release sdk sdk-full push_dev
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "Nextflow Fuzzball Plugin Build System"
	@echo "======================================"
	@echo ""
	@echo "Available targets:"
	@echo ""
	# assemble make target descriptions from special comments starting with '##' appended to the target line
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Environment Variables:"
	@echo "  SPEC_URL     OpenAPI spec URL (default: $(SPEC_URL))"
	@echo "  SPEC_FILE    Local OpenAPI spec file (defaults to latest vendored file - $(SPEC_FILE))"
	@echo ""
	@echo "Current Configuration:"
	@echo "  Spec:        $(SPEC)"
	@echo "  FB Version:  $(FB_VERSION)"
	@echo "  Version:     $(VERSION)"
	@echo "  Base Path:   $(BASEPATH)"

assemble: ## Build the plugin
	./gradlew assemble $(GRADLEW_PROPS)

clean: ## Clean build artifacts and temporary files
	rm -rf .nextflow*
	rm -rf work
	rm -rf build
	./gradlew clean

test: ## Run plugin unit tests
	./gradlew test $(GRADLEW_PROPS)

install: ## Install the plugin into local nextflow plugins dir
	./gradlew install $(GRADLEW_PROPS)

release: ## Publish the plugin to repository
	./gradlew releasePlugin $(GRADLEW_PROPS)

sdk: ## Generate Fuzzball SDK (groovy sources only)
	./gradlew generateFuzzballSdk $(GRADLEW_PROPS)

sdk-full: ## Generate complete Fuzzball SDK project in temp/fuzzball-sdk
ifneq ($(SPEC_URL),__none__)
	code-generation/generate --url "$(SPEC)" --keep temp/fuzzball-sdk
else
	code-generation/generate --file "$(SPEC)" --keep temp/fuzzball-sdk
endif

push_dev: assemble ## Push dev version to local plugin repository (requires push_dev.local script)
	if [ -e push_dev.local ] ; then \
	    ./push_dev.local v$(VERSION) $(FB_VERSION); \
	else \
	    echo "Create a 'push_dev' script to build the plugin and push it to a https or s3 accessible location"; \
	fi
