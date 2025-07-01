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

# temporary rule for pushing the plugin to S3
push: assemble
	aws s3 cp build/distributions/nf-fuzzball-$(VERSION).zip s3://co-ciq-misc-support/nf-fuzzball/v$(VERSION)/nf-fuzzball-$(VERSION)-stable-$(FB_VERSION).zip
