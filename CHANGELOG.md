# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

_No changelog was maintained before v0.2.0._

## [0.2.1] 2026-04-28

### Added

- **Nextflow ANSI output control**. A new `--ansi` / `--no-ansi` flag controls whether Nextflow uses
  ANSI log and summary output. Defaults to enabled.
- **`--version` flag**. The submission script now supports `--version` to print the installed version.

### Changed

- **Nextflow updated to 25.10.4**. The bundled Nextflow version used by the plugin has been updated.
- **Improved error handling**. Clearer error messages and more systematic logging configuration.

### Internal

- Gradle updated to 8.14.3.
- Migrated type checking from mypy to `ty` for Python code.
- Dependency bumps to address security advisories.

## [0.2.0] 2026-03-23

### Added

- **Renewable tokens**. The `nf-fuzzball-submit` submission script can now renew Fuzzball tokens
  when using direct or device-based authentication to allow long-running Nextflow pipelines.
- **Device flow login**. The `nf-fuzzball-submit` submission script can now use `--device` for
  the interactive, browser-based Fuzzball login flow.
- **Optional S3 egress for pipeline output**. A new `--egress-*` family of options allows pipeline
  output to be automatically copied to an S3 bucket at the end of a run. Environment variables can be
  used as defaults for egress options.
- **Configurable main job resources**. The main Nextflow controller job's CPU cores (`--cores`) and
  memory (`--memory`) are now configurable via CLI options.
- **`--fb-version` override**. The Fuzzball API version used by the submission script can now be
  overridden via `--fb-version`, useful when targeting non-default Fuzzball versions.
- **Fuzzball v3.1 and v3.2 support**. The Nextflow Groovy plugin now supports Fuzzball v3.1 and v3.2.
- **Submission script packaged as an installable Python package**. The submission script has been
  refactored from a single file into an installable `nf-fuzzball-submit` package with a proper CLI
  entry point, enabling `uv tool install` / `pip install` workflows.
- **Direct login for submission script**. The submission script can now authenticate directly against
  Keycloak without requiring a pre-existing Fuzzball context.

### Changed

- **Development CLI options grouped**. The `--fb-version` and related development/debugging options
  are now grouped under a dedicated section in `--help` output.

### Fixed

- **Ephemeral volumes excluded from Nextflow subtask mounts**. Nextflow child job workflows no longer
  attempt to mount ephemeral volumes.
- **Nextflow retry behavior**. Process-level retry configuration is now correctly passed through to
  the Fuzzball workflow config scope, preventing silent retry failures.
- **File size validation before upload**. Individual file size and total bundle size are now checked
  before attempting to bundle local files into the nextflow workflow.

### Internal

- Dependencies upgraded: `commons-lang3`, `okhttp3`.
