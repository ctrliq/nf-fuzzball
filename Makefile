# Build the plugin
assemble:
	./gradlew assemble

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
	./gradlew install

# Publish the plugin
release:
	./gradlew releasePlugin

# generate the Fuzzball SDK based on the stable cluster. This generates the
# code as it would be in a `make assemble` (i.e. only groovy sources in the build dir)
sdk:
	./gradlew generateSdk

# generate the Fuzzball SDK as a separate project in temp/fuzzball-sdk
sdk-full:
	code-generation/generate --keep temp/fuzzball-sdk
