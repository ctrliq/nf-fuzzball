# Build the plugin
SPEC_URL ?= https://api.stable.fuzzball.ciq.dev/v3/schema
SPEC_FILE ?= __none__

# Check for required tools
ifeq ($(shell command -v jq 2>/dev/null),)
  $(error "jq is required but not installed. Please install jq to continue.")
endif

ifeq ($(SPEC_FILE),__none__)
  ifeq ($(shell command -v curl 2>/dev/null),)
    $(error "curl is required but not installed. Please install curl to continue.")
  endif
  SPEC := $(SPEC_URL)
  FB_VERSION := $(shell curl -s "$(subst schema,version,$(SPEC_URL))" | jq -r '.version // ""')
  BASEPATH := $(shell curl -s "$(SPEC_URL)" | jq -r '.basePath')
else
  SPEC := $(SPEC_FILE)
  FB_VERSION := $(shell basename "${SPEC_FILE}" | sed -E 's/fuzzball-(v[^-]+)-openapi.json/\1/')
  BASEPATH := $(shell jq -r '.basePath' "$(SPEC_FILE)")
endif
ifeq ($(FB_VERSION),)
  $(error "Unable to detect fuzzball version from URL or filename")
endif

VERSION := $(shell ./gradlew properties | awk '/^version:/{print $$2}')
$(info "SPEC:           $(SPEC)")
$(info "FB VERSION:     $(FB_VERSION)")
$(info "PLUGIN VERSION: $(VERSION)")
$(info "BASEPATH:       $(BASEPATH)")

assemble:
	./gradlew assemble -PopenapiUrl=$(SPEC)

clean:
	rm -rf .nextflow*
	rm -rf work
	rm -rf build
	./gradlew clean

# Run plugin unit tests
test:
	./gradlew test

# Install the plugin into local nextflow plugins dir
install:
	./gradlew install -PopenapiUrl=$(SPEC)

# Publish the plugin
release:
	./gradlew releasePlugin -PopenapiUrl=$(SPEC)

# generate the Fuzzball SDK based on the stable cluster. This generates the
# code as it would be in a `make assemble` (i.e. only groovy sources in the build dir)
sdk:
	./gradlew generateSdk -PopenapiUrl=$(SPEC)

# generate the Fuzzball SDK as a separate project in temp/fuzzball-sdk
sdk-full:
ifeq ($(SPEC_FILE),__none__)
	code-generation/generate --url "$(SPEC)" --keep temp/fuzzball-sdk
else
	code-generation/generate --file "$(SPEC)" --keep temp/fuzzball-sdk
endif

# Rule for pushing dev versions of the plugin to a local plugin repository that can
# be used with --plugin-base-uri
# Depends on the script `push_dev.local` to work. This script is not included in the repository. Create
# your own to customize.
push_dev: assemble
	if [ -e push_dev.local ] ; then \
	    ./push_dev.local v$(VERSION) $(FB_VERSION); \
	else \
	    echo "Create a 'push_dev' script to build the plugin and push it to a https or s3 accessible location"; \
	fi
