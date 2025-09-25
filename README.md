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



## Building and using development versions of the nextflow plugin

Build the plugin from the current working tree and push it to a
location that is accessible via s3 or https from the Fuzzball
cluster.

```sh
make push_dev
```

This depends on a script called `push_dev.local` you can create to customize
where the plugin is pushed for use with your Fuzzball workflows. The plugin's
name has to match the pattern the submission script looks for. Here is an
example:

```sh
#! /bin/bash

ver="${1:-none}"
fb_ver="${2:=none}"
if [[ "${ver}${fb_ver}" =~ none ]] ; then
    echo "USAGE:  $0 PLUGIN_VERSION FUZZBALL_VERSION"
    echo "        PLUGIN_VERSION and FUZZBALL_VERSION are both expected to start with a v"
fi

aws s3 cp \
    build/distributions/nf-fuzzball-${ver}.zip \
    s3://MY_BUCKET/nf-fuzzball/${ver}/nf-fuzzball-${ver}-stable-${fb_ver}.zip
```

Note the naming pattern `${ver}/nf-fuzzball-${ver}-stable-${fb_ver}.zip` where
`$ver` is the full version of the plugin (e.g. 'v0.1.2') and `$fb_ver` is the
MAJOR.MINOR version of fuzzball to build against (e.v. 'v2.2'). To use this
build with the nf-fuzzball-submit script you would specify the location to
download from like so:

```sh
python submit_nextflow.py \
    --plugin-base-uri=s3://MY_BUCKET/MY_PREFIX/nf-fuzzball  \
    --s3-secret "secret://user/MY_S3_SECRET" \
    -- \
    nextflow run hello
```
