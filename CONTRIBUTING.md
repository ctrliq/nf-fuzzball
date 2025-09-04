# Contributing

## Requirements

- java >= 17
- nextflow >= 25.03.1-edge
- if using the `launcher.sh` script a clone of the nextflow repo in a sister
    directory. This is awkward and will not support all possible scenarios of
    plugin development
- **recommended** if not using the `launcher.sh`, you need to install
    nextflow somewhere. We added some rules to the Makefile to build and
    locally install the plugin for testing/experimentation. See below.
- groovy if you want to do some local exploration of groovy with the groovy
console.

## Fuzzball Groovy SDK Generation

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
# or to save to temp/fuzzball-sdk
make sdk-full
```


To build the plugin and install it locally to `~/.nextflow/plugins/nf-fuzzball-<VER>` use

```sh
git clone https://github.com/ctrliq/nf-fuzzball.git
cd nf-fuzzball
make install
# use `make install FB_TARGET=integration` for integration
```


> [!TIP]
> The exact version has to be specified. Otherwise nextflow will try to download the newest
> version which will fail. Note that at this point the nf-fuzzball plugin expects to be running within a Fuzzball
> workflow and therefore local installation is generally not yet useful.


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
        List<String> wfIds = apiExplorer.listWorkflows()
        if (wfIds && wfIds.size() > 0) {
            // i know that status is included in the response from listWorkflows but i'm testing the API here
            apiExplorer.worflowStatus(wfIds[0])
        }
        String id = apiExplorer.startWorkflow()

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

    List<String> listWorkflows() {
        List<String> workflowIds = []
        println '\n\n-- WorkflowServiceApi.listWorkflows() ------------------------------------------------------------'
        try {
            ListWorkflowsResponse resp = this.workflowService.listWorkflows(null, null, null, null, null)
            println "Found ${resp.workflows?.size() ?: 0} workflows"
            Map<String,Integer> counts = [:]
            if (!resp.workflows) {
                println "No workflows found"
                return workflowIds
            }
            for (Workflow wf : resp.workflows) {
                workflowIds << wf.id
                if (wf?.status) {
                    counts[wf.status.toString()] = (counts[wf.status.toString()] ?: 0) + 1
                } else {
                    counts['UNKNOWN'] = (counts['UNKNOWN'] ?: 0) + 1
                }
            }
            counts.each { k, v ->
                println "  ${k}: ${v}"
            }
            return workflowIds
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

## Branching Strategy

### Branch Structure

- main: Production-ready code, always deployable
- vMAJOR.MINOR.x: Release branches for major.minor versions (e.g., v0.1.x, v1.0.x)
- Feature branches: Short-lived branches for development

### Tagging Strategy

- vMAJOR.MINOR.0 tags on vMAJOR.MINOR.x branches (initial release)
- vMAJOR.MINOR.Z patch tags on vMAJOR.MINOR.x branches
- All tags follow semantic versioning

Example:
```
main ←────────────────────────────────────
↓
v0.1.x ── v0.1.0 ── v0.1.1 ── v0.1.2
↓
v1.0.x ── v1.0.0 ── v1.0.1
```

### Workflow Process

1. Feature Development: Create feature branch from main → PR to main
2. Release Preparation: Create vMAJOR.MINOR.x branch from main
3. Release Tagging: Tag vMAJOR.MINOR.0 on vMAJOR.MINOR.x branch
4. Patch Releases: Cherry-pick fixes to vMAJOR.MINOR.x → tag vMAJOR.MINOR.Z
5. The `build.gradle` version on main should be the next minor version up
   from the most recent release branch. That change is made after creation of
   a release branch.
