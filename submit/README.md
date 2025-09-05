# Submitting Nextflow Workflows to Fuzzball

This directory contains a helper script (`submit_nextflow.py`) for submitting
Nextflow workflows to Fuzzball using Python.

## Prerequisites

- Access to a Fuzzball deployment
  - Logged in to your Fuzzball deployment via the Fuzzball CLI will update
  `~/.config/fuzzball/config.yaml` with a valid token
- [`uv`](https://github.com/astral-sh/uv) installed for Python dependencies

## Quick Start

The following section will walk though getting your environment set up with
[`uv`](https://github.com/astral-sh/uv) and
[`direnv`](https://github.com/direnv/direnv).

### Running with uv

```sh
uv venv
uv pip install urllib3 pyyaml
uv run python submit_nextflow.py --help
```

### Setting up direnv

```sh
echo "source .venv/bin/activate" >> .envrc
direnv allow
./submit_nextflow.py --help
```

## Available Arguements

The table below outlines options that can be specified in the submission script,
if they are required, defaults, and a description of what the arguement does.
Below is the general format of calling the helper script using `uv`.

```sh
uv run python submit_nextflow.py [OPTIONS] -- [nextflow_cmd]
```

| Argument                  | Required | Default                        | Description                                                                                                                        |
|---------------------------|----------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `nextflow_cmd`            | Yes      | (none)                         | The Nextflow command to run (specified after `--`).                                                                                |
| `-c`, `--context`         | No       | (active context in config)     | Name of the Fuzzball context to use from config.yaml. Defaults to the active context in the config file.                           |
| `-v`, `--verbose`         | No       | False                          | Dump the workflow before submitting and add debug logging.                                                                         |
| `--fuzzball-config`       | No       | `~/.config/fuzzball/config.yaml` | Path to the Fuzzball configuration file.                                                                                         |
| `-n`, `--dry-run`         | No       | False                          | Don't submit the workflow, just print it.                                                                                          |
| `--job-name`              | No       | (UUID from command)            | Name of the Fuzzball workflow running the Nextflow controller job. Defaults to a UUID seeded by the full Nextflow command.         |
| `--nextflow-work-base`    | No       | `nextflow/executions`          | Base directory for Nextflow execution paths.                                                                                       |
| `--nf-fuzzball-version`   | No       | `0.0.1`                        | nf-fuzzball plugin version.                                                                                                        |
| `--nextflow-version`      | No       | `25.05.0-edge`                 | Nextflow version to use in the Fuzzball job.                                                                                       |
| `--timelimit`             | No       | `8h`                           | Timelimit for the pipeline job.                                                                                                    |
| `--scratch-volume`        | No       | `volume://user/ephemeral`      | Ephemeral scratch volume reference.                                                                                                |
| `--data-volume`           | No       | `volume://user/persistent`     | Persistent data volume reference.                                                                                                  |
| `--nf-core`               | No       | False                          | Use nf-core conventions.                                                                                                           |
| `--queue-size`            | No       | 20                             | Queue size for the Fuzzball executor (number of jobs that can be queued at once).                                                  |
| `--plugin-base-uri`       | No       | Downloads from this repo       | Base URI for the nf-fuzzball plugin. The submission script expects to find a zip file at                                           |
|                           |          |                                | `<plugin-base-uri>/v<version>/nf-fuzzball-<version>-stable-v<fuzzball-version>.zip`                                                |
| `--s3-secret`             | Maybe    | (none)                         | Reference for fuzzball S3 secret used to pull the nf-fuzzball plugin if the base URI for the plugin download is a S3 URI.          |
| `--ca-cert`               | Maybe    | (none)                         | If using a self-signed certificate for Fuzzball, the CA certificate used to sign the Fuzzball certificate is required              |

## Example Usage

```sh
# Login into active Fuzzball context to set up valid token in
# ~/.config/fuzzball/config.yaml

fuzzball context login
```

Submit the nextflow hello-world workflow
```sh
uv run python submit_nextflow.py -- \
    nextflow run \
      -profile fuzzball \
      -with-report report.html \
      -with-trace \
      -with-timeline timeline.html \
      hello
```

Submit nf-core/demultiplex workflow into Fuzzball such that each child jobs
runs as Fuzzball workflows
```sh
uv run python submit_nextflow.py --job-name demux-test \
  --nf-core -- \
    nextflow run nf-core/demultiplex \
      -profile test,fuzzball \
      --outdir /data/nextflow/out/demux-test-out
```

## Using the Plugin from the Main Branch
