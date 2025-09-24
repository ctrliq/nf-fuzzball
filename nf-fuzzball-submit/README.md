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
uv tool install git+https://github.com/ctrliq/nf-fuzzball.git@main#subdirectory=nf-fuzzball-submit
# from a release
uv tool install git+https://github.com/ctrliq/nf-fuzzball.git@v0.2.0#subdirectory=nf-fuzzball-submit

nf-fuzzball-submit --help
```

To uninstall you can use
```sh
uv tool uninstall nf-fuzzball-submit
```

Installation into a virtual environment
```sh
uv venv
uv pip install git+https://github.com/ctrliq/nf-fuzzball.git@main#subdirectory=nf-fuzzball-submit
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
python -m pip install git+https://github.com/ctrliq/nf-fuzzball.git@main#subdirectory=nf-fuzzball-submit
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

Authenticate directly using username/password. This method is used if a username is specified.

```sh
FUZZBALL_API_URL="https://api.example.com"
FUZZBALL_AUTH_URL="https://auth.example.com/auth/realms/fuzzball"
FUZZBALL_USER="user@example.com"
FUZZBALL_ACCOUNT_ID="account-id"
read -rs FUZZBALL_PASSWORD  ## securely read password without echoing to the terminal
***********
export FUZZBALL_API_URL FUZZBALL_AUTH_URL FUZZBALL_USER FUZZBALL_ACCOUNT_ID FUZZBALL_PASSWORD

nf-fuzzball-submit -- nextflow run -profile fuzzball hello
```

## Command Line Options

#### Arguments

The nextflow command to be executed is specified after a `--` following the options described below.

General options

| Argument                | Default                     | Description                                                         |
|-------------------------|-----------------------------|---------------------------------------------------------------------|
| `-v`, `--verbose`       | False                       | Dump the workflow before submitting and add debug logging           |
| `-n`, `--dry-run`       | False                       | Don't submit the workflow, just print it                            |
| `--job-name`            | (UUID from command)         | Name of the Fuzzball workflow                                       |
| `--nextflow-work-base`  | `/data/nextflow/executions` | Base directory for Nextflow execution paths                         |
| `--nf-fuzzball-version` | `0.2.0`                     | nf-fuzzball plugin version                                          |
| `--nextflow-version`    | `25.05.0-edge`              | Nextflow version to use in the Fuzzball job                         |
| `--timelimit`           | `8h`                        | Timelimit for the pipeline job                                      |
| `--scratch-volume`      | `volume://user/ephemeral`   | Ephemeral scratch volume reference                                  |
| `--data-volume`         | `volume://user/persistent`  | Persistent data volume reference                                    |
| `--nf-core`             | False                       | Use nf-core conventions                                             |
| `--queue-size`          | 20                          | Queue size for the Fuzzball executor                                |
| `--plugin-base-uri`     | GitHub releases             | Base URI for the nf-fuzzball plugin                                 |
| `--s3-secret`           | (none)                      | Fuzzball S3 secret for plugin download if using S3 URI              |
| `--ca-cert`             | (none)                      | CA certificate for Fuzzball clusters with a self-signed certificate |

Options for authenticting via the Fuzzball config file:

| Argument            | Default                          | Description                                          |
|---------------------|----------------------------------|------------------------------------------------------|
| `-c`, `--context`   | (active context in config)       | Name of the Fuzzball context to use from config.yaml |
| `--fuzzball-config` | `~/.config/fuzzball/config.yaml` | Path to the Fuzzball configuration file              |

Options for autheniting via direct login:

| Argument       | Default              | Description                             |
|----------------|----------------------|-----------------------------------------|
| `--api-url`    | $FUZZBALL_API_URL    | API URL of Fuzzball cluster []          |
| `--auth-url`   | $FUZZBALL_AUTH_URL   | AUTH URL of Fuzzball cluster []         |
| `--user`       | $FUZZBALL_USER       | Username/email for direct login []      |
| `--password`   | $FUZZBALL_PASSWORD   | Prompt for password for direct login [] |
| `--account-id` | $FUZZBALL_ACCOUNT_ID | Fuzzball account ID for direct login [] |

If a user has been specified with `--user` or by setting `$FUZZBALL_USER` it is
assumed that direct login authentication should be used.


## Development

### Setting up the development environment

```bash
git clone <repository>
cd nf-fuzzball-submit
uv sync --dev
```

### Code formatting

```bash
uv run ruff format
uv run isort src/
```

### Type checking

```bash
uv run mypy src/
```

There are two ways to run a development version of this script:

1. Build the corresponding `nf-fuzzball` nextflow plugin and push it to a S3
   bucket or a location accessible via https from the Fuzzball cluster (see main
   Readme). You can then use the development version by specifying `--plugin-base-uri`
   and (of S3) `--s3-secret`.
2. You can specify a release version of the actual plugin with `--nf-fuzzball-release`
   which will obtain the plugin from this repository.
