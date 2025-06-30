# Fuzzball Executor Plugin for Nextflow

The following repository contains source code for a Nextflow plugin implementing
support for CIQ's product [Fuzzball](https://ciq.com/products/fuzzball/). This
plugin enables use of high quality, community maintained workflows provided by
the [nf-core](https://nf-co.re) on Fuzzball.

## Overview

A submission script `submit/submit_nextflow.py` is provided which submits a
parent workflow which starts the Nextflow workflow in a Fuzzball deployment. The
parent workflow performs the following tasks to setup the environment to submit
child Nextflow jobs to Fuzzball:

1. Sets up the Fuzzball executor plugin in the parent workflow though Fuzzball
file ingress and the `setup` job.
2. Packages up your local active Fuzzball context and valid token as a Fuzzball
secret and sets up the parent workflow to use it. This task is also done in the
`setup` job of the parent workflow that is submited.

When the Nextflow workflow is executed within Fuzzball using the Fuzzball
executor, child jobs are translated into Fuzzball workflows (Fuzzfiles) and
submited to your Fuzzball deployment. If you are running on-premise, jobs should
be scheduled on compute resources running Fuzzball Substrate that have available
resources. If you are running in the cloud, instances will be provisioned to run
Nextflow child jobs.

For more information on submission script usage, please see the
[submission script usage documentation](submit/Readme.md).

## Introduction

[Nextflow](https://www.nextflow.io/ ) is a workflow orchestration tool with many
possible executors (local, slurm, aws batch, kubernetes, …). We have at least
one potential client who uses nextflow and nextflow in general is very widely
used in the genomics/bioinformatics space and there are high quality community
maintained standard workflows provided by the [nf-core](https://nf-co.re/)
project.

Nextflow can provided needed tools to tasks it executes via a number of
mechanisms including defining runtime containers (various container engines
supported) for each task or using conda environments. The latter is considerd a
last resort.

It would be advantageous if there was a maintainable mechanism for giving
Fuzzball customers access to these pipelines. There are three possible meachanisms
to do so:

1. Run a single-job Fuzzball workflow with nextflow running in local mode as the
   single job parallelizing only within the resources available to the job. This
   would in essence be similar to running this in local mode directly on a local
   system except that it would be easier to scale out. This would require either
   using conda environments to provide dependencies or creating a single
   container for the fuzzball job that includes all the required tools. I
   attempted to do this with conda environments using the
   [nf-core/rnaseq](https://nf-co.re/rnaseq/3.18.0/) and it did not work well
   due to frequent conda issues. Likely due to conda not being a well supported
   mechanism for providing dependencies to nextflow pipelines
2. Manual/(semi-)automatic translation of existing pipelines into native
   Fuzzball pipelines. Static translation of an abstract nextfow workflow
   definition with a configuration into a Fuzzfile may be difficult if there is
   dynamic (run-time) modification of the DAG based on the outcome of certain
   jobs. Manual/(semi-)automatic translation may result in high quality pipelines
   but will require ongoing efforts to keep in sync with nf-core
3. Creating a executor plugin that would allow nextflow to natively use fuzzball
   as an execution engine. This is what this repository will in the end
   hopefully implement. Because of the way nextflow likes to handle and track
   jobs this means that individual tasks will probably have to be submitted as
   individual fuzzball workflows (though task arrays for parallelization instead
   of individual workflows should be possible). With this we could benefit from
   all the features of nextflow and could allow customers easy access to
   existing standard tools and workflows. One downside may be that the nextflow
   executor would treat fuzzball like a more common scheduler rather than a
   workflow execution engine in its own right.

## References

Some relevant links (h/t Brian for some of them)

- Brian pointed to Rescale's Nextflow plugin  https://github.com/rescale/nf-rescale-hpc
- general nextflow information:
   - Nextflow docs: https://www.nextflow.io/
   - Nextflow repo: https://github.com/nextflow-io/nextflow
   - Example plugin repo: https://github.com/nextflow-io/nf-hello
   - Plugin docs: https://www.nextflow.io/docs/latest/plugins.html
- Available plugins:
   ```console
   $ curl -s https://raw.githubusercontent.com/nextflow-io/plugins/refs/heads/main/plugins.json \
   | jq -r '.[] | [.id, .releases[0].url | sub("/releases/.*$"; "")] | @tsv' \
   | column -t

   nf-amazon        https://github.com/nextflow-io/nf-amazon
   nf-console       https://github.com/nextflow-io/nf-console
   nf-google        https://github.com/nextflow-io/nf-google
   nf-ignite        https://github.com/nextflow-io/nf-ignite
   nf-tower         https://github.com/nextflow-io/nf-tower
   nf-ga4gh         https://github.com/nextflow-io/nf-ga4gh
   xpack-amzn       https://github.com/seqeralabs/xpack-amzn
   nf-azure         https://github.com/nextflow-io/nf-azure
   xpack-google     https://github.com/seqeralabs/xpack-google
   nf-hello         https://github.com/nextflow-io/nf-hello
   nf-sqldb         https://github.com/nextflow-io/nf-sqldb
   nf-wr            https://github.com/nextflow-io/nf-wr
   nf-codecommit    https://github.com/nextflow-io/nf-codecommit
   nf-wave          https://github.com/nextflow-io/nf-wave
   nf-quilt         https://github.com/nextflow-io/nf-quilt
   nf-synapse       https://github.com/Sage-Bionetworks-Workflows/nf-synapse
   nf-prov          https://github.com/Sage-Bionetworks-Workflows/nf-prov
   nf-cws           https://github.com/CommonWorkflowScheduler/nf-cws
   nf-jarvice       https://github.com/nimbix/nf-jarvice
   nf-validation    https://github.com/nextflow-io/nf-validation
   nf-float         https://github.com/MemVerge/nf-float
   nf-cloudcache    https://github.com/nextflow-io/nf-cloudcache
   nf-weblog        https://github.com/nextflow-io/nf-weblog
   nf-dotenv        https://github.com/fulcrumgenomics/nf-dotenv
   nf-iridanext     https://github.com/phac-nml/nf-iridanext
   nf-co2footprint  https://github.com/nextflow-io/nf-co2footprint
   yellowdog        https://github.com/yellowdog/nextflow-plugin-public
   nf-ffq           https://github.com/nextflow-io/nf-ffq
   nf-gpt           https://github.com/nextflow-io/nf-gpt
   nf-boost         https://github.com/bentsherman/nf-boost
   nf-schema        https://github.com/nextflow-io/nf-schema
   nf-nomad         https://github.com/nextflow-io/nf-nomad
   nf-tencentcloud  https://github.com/Tencent/nf-tencentcloud
   nf-snowflake     https://github.com/Snowflake-Labs/nf-snowflake
   nf-parquet       https://github.com/nextflow-io/nf-parquet
   nf-pgcache       https://github.com/edn-es/nf-pgcache
   nf-datatrail     https://github.com/Lehmann-Fabian/nf-datatrail
   nf-k8s           https://github.com/nextflow-io/nf-k8s
   nf-lamin         https://github.com/laminlabs/nf-lamin
   ```
- Brian found this very helpful tutorial video with Ben Sherman and Phil Ewels: https://nextflow.io/podcast/2024/ep35_nextflow_plugins.html
