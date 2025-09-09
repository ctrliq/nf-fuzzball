# Build the plugin

FB_TARGET ?= stable
ifeq ($(FB_TARGET),integration)
  OPENAPI_URL := https://api.integration.fuzzball.ciq.dev/v2/schema
  VERSION_URL := https://api.integration.fuzzball.ciq.dev/v2/version
else
    OPENAPI_URL := https://api.stable.fuzzball.ciq.dev/v2/schema
    VERSION_URL := https://api.stable.fuzzball.ciq.dev/v2/version
endif

VERSION := $(shell ./gradlew properties | awk '/^version:/{print $$2}')
FB_VERSION := $(shell curl -s "$(VERSION_URL)" | jq -r '.version')

assemble:
	./gradlew assemble -PopenapiUrl=$(OPENAPI_URL)

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
	./gradlew install -PopenapiUrl=$(OPENAPI_URL)

# Publish the plugin
release:
	./gradlew releasePlugin -PopenapiUrl=$(OPENAPI_URL)

# generate the Fuzzball SDK based on the stable cluster. This generates the
# code as it would be in a `make assemble` (i.e. only groovy sources in the build dir)
sdk:
	./gradlew generateSdk -PopenapiUrl=$(OPENAPI_URL)

# generate the Fuzzball SDK as a separate project in temp/fuzzball-sdk
sdk-full:
	code-generation/generate --url "$(OPENAPI_URL)" --keep temp/fuzzball-sdk

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
