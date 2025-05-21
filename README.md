# Fuzzball executor plugin for nextflow

## Current state

> [!NOTE]
> **Work In Progress**. This plugin is not functional yet.

This is not yet a functional nextflow plugin. It contains a skeleton fuzzball project plus
code and templates to automatically generate a modern-ish groovy Fuzzball SDK with the
gradle tooling to integrate the generated code into a build.

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

## Development

Requirements:
  - java >= 17
  - nextflow >= 25.03.1-edge
   - if using the `launcher.sh` script a clone of the nextflow repo in a sister
      directory. This is awkward and will not support all possible scenarios of
      plugin development
   - **recommended** if not using the `launcher.sh`, you need to install
     nextflow somewhere. I've added some rules to the Makefile to build and
     locally install the plugin for testing/experimentation. See below.
  - groovy if you want to do some local exploration of groovy with the groovy
    console. Otherwise i don't think you need it since it gets pulled in during
    build time as a library.

The repository uses the [openapi generator](https://openapi-generator.tech/). No
install is necessary as the generator script downloads the correct version. The
code generation is based off the stable cluster and uses extensive custom
templates (see the `code-generation` directory). Generated SDK code is _not_
included in the repository. It gets written to the plugin's build directory.
Code generation is triggered during build if necessary. The generator itself
generates a self-contained gradle based project but for the plugin build only
the groovy source files are retained. If you want to manually generate the
groovy SDK you can run

```sh
code-generation/generate --keep /path/to/where/you/want/the/project
```

> [!WARNING]
> There is still an issue with date conversions in the auto-generated API. Working on resolving
> that.

To build the plugin and install it locally to `~/.nextflow/plugins/nf-fuzzball-<VER>` use

```sh
git clone ...
cd nf-fuzzball
make install
```

The repository contains a `nextflow.config` file which will activate the plugin:

```
plugins {
  id 'nf-fuzzball@0.0.1'
}

fuzzball {
  fuzzball_config_file = "~/.config/fuzzball/config.yaml"
}
```

> [!TIP]
> The exact version has to be specified. Otherwise nextflow will try to download the newest
> version which will fail.

The plugin doesn't do anything yet but if you run

```sh
nextflow run hello
```

you will be running nextflow with the plugin activated


```sh
git clone 
```

### Example code using the generated SDK

```groovy
package com.ciq.fuzzball

import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.DumperOptions
import com.ciq.fuzzball.api.ApiConfig
import com.ciq.fuzzball.api.WorkflowServiceApi
import com.ciq.fuzzball.model.StartWorkflowRequest
import com.ciq.fuzzball.model.WorkflowDefinition
import com.ciq.fuzzball.model.ListWorkflowsResponse
import com.ciq.fuzzball.model.WorkflowIDResponse
import com.ciq.fuzzball.model.GetWorkflowStatusResponse
import com.ciq.fuzzball.model.WorkflowStatus
import com.ciq.fuzzball.model.Workflow
import com.ciq.fuzzball.api.ApiUtils.ApiException

/**
 * Entry point for the fuzzball API exxploration. Does more than listing workflows now.
 *
 * This class contains the main method to start the application.
 */
@CompileStatic
class Main {

    /**
     * Main method to start the application.
     * @param args command line arguments
     */
    static void main(String[] args) {
        // Create an instance of ApiExplorer to explore the API
        ApiExplorer apiExplorer = new ApiExplorer()
        apiExplorer.listWorkflows()
        String id = apiExplorer.startWorkflow()
        if (id) {
            apiExplorer.worflowStatus(id)
        }
    }

}

/**
 * ApiExplorer class to explore the API and perform various operations.
 */
@CompileStatic
class ApiExplorer {

    private ApiConfig apiConfig
    private WorkflowServiceApi workflowService

    ApiExplorer() {
        this.apiConfig = ApiConfig.fromFuzzballConfig()
        this.workflowService = new WorkflowServiceApi(this.apiConfig)
    }

    void listWorkflows() {
        println '\n\n-- WorkflowServiceApi.listWorkflows() ------------------------------------------------------------'
        try {
            ListWorkflowsResponse resp = this.workflowService.listWorkflows(null, null, null, null, null)
            println "Found ${resp.workflows?.size() ?: 0} workflows"
            Map<String,Integer> counts = [:]
            if (!resp.workflows) {
                println "No workflows found"
                return
            }
            for (Workflow wf : resp.workflows) {
                if (wf?.status) {
                    counts[wf.status.toString()] = (counts[wf.status.toString()] ?: 0) + 1
                } else {
                    counts['UNKNOWN'] = (counts['UNKNOWN'] ?: 0) + 1
                }
            }
            counts.each { k, v ->
                println "  ${k}: ${v}"
            }
        } catch (ApiException e) {
            println "API error: ${e.statusCode} ${e.statusMessage}"
        } catch (IOException e) {
            println "IO error: ${e.message}"
        } catch (Exception e) {
            println "Unexpected error: ${e.message}"
            e.printStackTrace()
        }

    }

    String startWorkflow() {
        println '\n\n-- WorkflowServiceApi.startWorkflow() ------------------------------------------------------------'
        String wf = '''
version: v1
jobs:
  printer:
    image:
      uri: docker://docker.io/alpine:latest
    policy:
      timeout:
        execute: 6m0s
    command:
      - /bin/sh
      - '-c'
      - for i in $(seq 1 300); do echo $i; sleep 1; done
    resource:
      cpu:
        cores: 1
      memory:
        size: 1GB
'''
        Yaml yaml = new Yaml()
        WorkflowDefinition wfDef = yaml.load(wf) as WorkflowDefinition
        StartWorkflowRequest startWf = new StartWorkflowRequest(
                name: 'fuzzball-test',
                definition: wfDef,
        )
        WorkflowIDResponse resp
        try {
            resp = this.workflowService.startWorkflow(startWf)
        } catch (ApiException e) {
            println "API error: ${e.statusCode} ${e.statusMessage}"
        } catch (IOException e) {
            println "IO error: ${e.message}"
        } catch (Exception e) {
            println "Unexpected error: ${e.message}"
            e.printStackTrace()
        }
        println "Started a new workflow with id  ${resp?.id}"
        return resp?.id
    }

    void worflowStatus(String id) {
        println '\n\n-- WorkflowServiceApi.workflowStatus() ------------------------------------------------------------'
        GetWorkflowStatusResponse resp
        try {
            resp = this.workflowService.getWorkflowStatus(id)
        } catch (ApiException e) {
            println "API error: ${e.statusCode} ${e.statusMessage}"
        } catch (IOException e) {
            println "IO error: ${e.message}"
        } catch (Exception e) {
            println "Unexpected error: ${e.message}"
            e.printStackTrace()
        }
        println "Workflow ${id} status: ${resp?.workflowStatus}"
    }

    /**
     * Pretty prints an object as YAML.
     * @param obj the object to be pretty printed
     * @return the pretty printed YAML string
     */
    static String prettyPrintYaml(Object obj) {
        DumperOptions options = new DumperOptions()
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
        options.setPrettyFlow(true)
        Yaml yaml = new Yaml(options)
        return yaml.dump(obj)
    }

    /**
     * Reads an environment variable and returns its value.
     * @param envVarName the name of the environment variable
     * @return the value of the environment variable, or null if not set
     */
    protected String getEnv(String envVarName) {
        Map<String,String> env = System.getenv() // task.getEnvironment()
        return env[envVarName]
    }

}



```