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
[submission script usage documentation](submit/README.md).
