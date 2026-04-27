# Submitting Nextflow Workflows to Fuzzball

Helper to submit Nextflow pipelines to Fuzzball using the nf-fuzzball plugin.

## Prerequisites

- Access to a Fuzzball cluster
- Python >= 3.10
- [`uv`](https://github.com/astral-sh/uv) or `pip`

## Installation

### Using uv (recommended)

Installation as a tool (see the [uv tool documentation](https://docs.astral.sh/uv/concepts/tools/#tool-versions))

```sh
# from the main branch
uv tool install "git+https://github.com/ctrliq/nf-fuzzball.git@main#subdirectory=nf-fuzzball-submit"
# from a release
uv tool install "git+https://github.com/ctrliq/nf-fuzzball.git@v0.2.1#subdirectory=nf-fuzzball-submit"

nf-fuzzball-submit --help
```

To uninstall you can use

```sh
uv tool uninstall nf-fuzzball-submit
```

Installation into a virtual environment

```sh
uv venv
uv pip install "git+https://github.com/ctrliq/nf-fuzzball.git@main#subdirectory=nf-fuzzball-submit"
uv run nf-fuzzball-submit --help
## or
source .venv/bin/activate
nf-fuzzball-submit --help
```

### Using pip

Install into a virtual environment

```bash
python -m venv nf-fuzzball
source nf-fuzzball/bin/activate
python -m pip install "git+https://github.com/ctrliq/nf-fuzzball.git@main#subdirectory=nf-fuzzball-submit"
```

## Configuration

The tool supports two authentication methods for Fuzzball:

### 1. Config File Authentication (Default)

Uses the Fuzzball CLI configuration file at `${XDG_CONFIG_HOME:-$HOME/.config}/fuzzball/config.yaml`:

```sh
# Login to set up the config file and update your Fuzzball API token
fuzzball context login

# Submit hello-world workflow
nf-fuzzball-submit -- \
    nextflow run \
      -profile fuzzball \
      -with-report report.html \
      -with-trace \
      -with-timeline timeline.html \
      hello
```

### 2. Direct Login Authentication

Authenticate directly using username/password. This method is used if a username is specified via `--user` or `$FUZZBALL_USER`.

```sh
FUZZBALL_API_URL="https://api.example.com"
FUZZBALL_AUTH_URL="https://auth.example.com/auth/realms/fuzzball"
FUZZBALL_USER="user@example.com"
FUZZBALL_ACCOUNT_ID="account-id"
read -rs FUZZBALL_PASSWORD  ## securely read password without echoing to the terminal
export FUZZBALL_API_URL FUZZBALL_AUTH_URL FUZZBALL_USER FUZZBALL_ACCOUNT_ID FUZZBALL_PASSWORD

nf-fuzzball-submit -- nextflow run -profile fuzzball hello
```

If `FUZZBALL_API_URL`, `FUZZBALL_AUTH_URL`, and `FUZZBALL_ACCOUNT_ID` or their corresponding
CLI options are not provided and a fuzzball configuration file exists, the values are parsed
from that file. In that case, the minimal command would be:

```sh
nf-fuzzball-submit --user user@example.com -- nextflow run -profile fuzzball hello
```

### 3. Device Flow Authentication

Authenticate interactively via the browser. This method is used if `--device` is specified.
The tool prints a URL and a code; open the URL in a browser, enter the code, and the
submission continues once authorization is confirmed.

```sh
nf-fuzzball-submit \
    --api-url "https://api.example.com" \
    --auth-url "https://auth.example.com/auth/realms/fuzzball" \
    --account-id "account-id" \
    --device \
    -- nextflow run -profile fuzzball hello
```

If `FUZZBALL_API_URL`, `FUZZBALL_AUTH_URL`, and `FUZZBALL_ACCOUNT_ID` or their corresponding
CLI options are not provided and a fuzzball configuration file exists, the values are parsed
from that file. In that case the minimal command would be:

```sh
nf-fuzzball-submit --device -- nextflow run -profile fuzzball hello
```

## Command Line Options

### Arguments

The nextflow command to be executed is specified after a `--` following the options described below.

General options

| Argument               | Default                     | Description                                                         |
|------------------------|-----------------------------|---------------------------------------------------------------------|
| `-h`, `--help`         | n/a                         | show this help message and exit                                     |
| `--version`            | n/a                         | show program's version number and exit                              |
| `-v`, `--verbose`      | False                       | Enable verbose logging from the submission script                   |
| `--ansi` / `--no-ansi` | True                        | Enable Nextflow ANSI log and summary output                         |
| `-n`, `--dry-run`      | False                       | Print the workflow without submitting                               |
| `--job-name`           | (UUID from command)         | Name of the Fuzzball workflow                                       |
| `--nextflow-work-base` | `/data/nextflow/executions` | Base directory for Nextflow execution paths                         |
| `--nextflow-version`   | `25.10.4`                   | Nextflow version to use in the Fuzzball job                         |
| `--timelimit`          | `8h`                        | Timelimit for the pipeline job                                      |
| `--memory`             | `4GB`                       | Memory allocated for the Nextflow controller job                    |
| `--cores`              | `1`                         | Cores allocated for the Nextflow controller job                     |
| `--scratch-volume`     | `volume://user/ephemeral`   | Ephemeral scratch volume reference                                  |
| `--data-volume`        | `volume://user/persistent`  | Persistent data volume reference                                    |
| `--nf-core`            | False                       | Use nf-core conventions                                             |
| `--queue-size`         | `20`                        | Queue size for the Fuzzball executor                                |
| `--ca-cert`            | (none)                      | CA certificate for Fuzzball clusters with a self-signed certificate |

Options for authenticating via the Fuzzball config file:

| Argument            | Default                          | Description                                          |
|---------------------|----------------------------------|------------------------------------------------------|
| `-c`, `--context`   | (active context in config)       | Name of the Fuzzball context to use from config.yaml |
| `--fuzzball-config` | `~/.config/fuzzball/config.yaml` | Path to the Fuzzball configuration file              |

Options for authenticating via direct or device login:

| Argument       | Default                | Description                                                            |
|----------------|------------------------|------------------------------------------------------------------------|
| `--api-url`    | `$FUZZBALL_API_URL`    | API URL of Fuzzball cluster                                            |
| `--auth-url`   | `$FUZZBALL_AUTH_URL`   | Auth URL of Fuzzball cluster                                           |
| `--user`       | `$FUZZBALL_USER`       | Username/email for direct login                                        |
| `--password`   | (flag)                 | Prompt for password interactively; otherwise uses `$FUZZBALL_PASSWORD` |
| `--device`     | False                  | Use device authorization grant (browser-based login)                   |
| `--account-id` | `$FUZZBALL_ACCOUNT_ID` | Fuzzball account ID                                                    |

If `--user` or `$FUZZBALL_USER` is set, direct login is used. If `--device` is set, device flow
is used (and `--user`/`--password` are ignored).

Options for optional S3 egress of pipeline results:

| Argument             | Default                                              | Description                                                |
|----------------------|------------------------------------------------------|------------------------------------------------------------|
| `--egress-source`    | (none)                                               | Path under `/data` to copy to S3 after the run             |
| `--egress-s3-dest`   | (none)                                               | S3 URI to copy results to (e.g., `s3://my-bucket/results`) |
| `--egress-s3-aki`    | `$FUZZBALL_EGRESS_S3_AKI`                            | Fuzzball secret containing the AWS access key ID           |
| `--egress-s3-sak`    | `$FUZZBALL_EGRESS_S3_SAK`                            | Fuzzball secret containing the AWS secret access key       |
| `--egress-s3-region` | `$FUZZBALL_EGRESS_S3_REGION` / `$AWS_DEFAULT_REGION` | AWS region where the bucket is located                     |
| `--egress-timelimit` | `4h`                                                 | Timelimit for the egress job                               |

`--egress-source` and `--egress-s3-dest` must both be specified together, and the three credential
options (`--egress-s3-aki`, `--egress-s3-sak`, `--egress-s3-region`) must be provided either via
CLI flags or their corresponding environment variables.

Options for development:

| Argument                | Default         | Description                                             |
|-------------------------|-----------------|---------------------------------------------------------|
| `--nf-fuzzball-version` | script version  | nf-fuzzball plugin version                              |
| `--plugin-base-uri`     | GitHub releases | Base URI for the nf-fuzzball plugin                     |
| `--s3-secret`           | (none)          | Fuzzball S3 secret for plugin download if using S3 URI  |
| `--fb-version`          | (auto-detected) | Override the Fuzzball API version (e.g., `v3.2`)        |

## Development

### Setting up the development environment

```sh
git clone <repository>
cd nf-fuzzball-submit
uv sync --dev
```

### Running a development version of the submission tool

There are two ways to run a development version of the submission tool:

1. Build the corresponding `nf-fuzzball` nextflow plugin and push it to a S3
   bucket or a location accessible via https from the Fuzzball cluster (see main
   Readme). You can then use the development version by specifying `--plugin-base-uri`
   and (of S3) `--s3-secret`.
2. You can specify a release version of the actual plugin with `--nf-fuzzball-version`
   which will obtain the plugin from this repository.

### Code formatting

```sh
uv run ruff format
```

### Type checking

```sh
uv run ty check src/
```

### Linting

```sh
uv ruff check
```

### Running tests

Run all tests

```bash
uv run pytest
```

Run with coverage

```bash
uv run pytest --cov=nf_fuzzball_submit --cov-report=html
```

Run specific test files

```bash
uv run pytest tests/test_models.py -v
```

Run tests excluding slow/integration tests

```bash
uv run pytest -m "not integration"
```

### Using development versions of this script
