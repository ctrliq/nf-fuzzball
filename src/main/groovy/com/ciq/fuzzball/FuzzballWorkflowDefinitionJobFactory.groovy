package com.ciq.fuzzball


import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j

import com.ciq.fuzzball.model.Policy
import com.ciq.fuzzball.model.Timeout
import com.ciq.fuzzball.model.WorkflowDefinitionJob
import com.ciq.fuzzball.model.WorkflowDefinitionJobResource
import com.ciq.fuzzball.model.WorkflowDefinitionJobResourceCpu
import com.ciq.fuzzball.model.WorkflowDefinitionJobResourceMemory
import nextflow.processor.TaskRun


@CompileStatic
@Slf4j
class FuzzballWorkflowDefinitionJobFactory {

    static WorkflowDefinitionJob create (TaskRun task){
        WorkflowDefinitionJob job = new WorkflowDefinitionJob()
        // task.getName() should return a unique identifier. I think we want to avoid a default value here
        // in case we end up with more than one job per worklow at some point in the future.
        job.name = toSafeYamlKey(task.getName())
        job.image = getNextflowTaskContainer(task) as java.net.URI
        job.setResource(getNextflowComputeResources(task))
        job.setCommand(getNextflowCommand(task))
        job.setCwd(getNextflowTaskCwd(task))
        job.setPolicy(getNextflowTimeoutPolicy(task))
        return job
    }

    static String toSafeYamlKey(String input) {
        if (!input) return "_"
        String key = input
            .replaceAll(/[^a-zA-Z0-9_]/, "-") // Replace non-alphanumeric with -
            .replaceAll(/-+/, "-")            // Collapse multiple underscores
            .replaceAll(/^-+|-+$/, "")        // Trim leading/trailing underscores
            .toLowerCase()
        if (!key || !key[0].matches(/[a-z_]/)) {
            key = "_" + key
        }
        return key
    }

    static String getNextflowTaskContainer(TaskRun task) {
        if (task.config.getContainer()) {
            return "docker://" + task.config.getContainer().toString()
        } else {
            throw new IllegalArgumentException("A container must be specified for the task.")
        }
    }

    static WorkflowDefinitionJobResource getNextflowComputeResources(TaskRun task) {
        WorkflowDefinitionJobResource resources = new WorkflowDefinitionJobResource()
        resources.setCpu(new WorkflowDefinitionJobResourceCpu().setCores(getNextflowTaskCpus(task)))
        resources.setMemory(new WorkflowDefinitionJobResourceMemory().setSize(getNextflowTaskMemory(task)))
        return resources
    }

    static Long getNextflowTaskCpus(TaskRun task) {
        return task.config.getCpus().toLong() ?: 1 // Default to 1 CPU if not specified
    }

    static String getNextflowTaskMemory(TaskRun task) {
        return task.config.getMemory()?.toGiga()?.toString() + "GiB" ?: "1GiB" // Default to 1 GiB if not specified
    }

    static String getNextflowTaskCwd(TaskRun task) {
        return task.workDir.toString() 
    }

    static List<String> getNextflowCommand(TaskRun task) {
        return task.config.getShell() + task.CMD_RUN // Command to run
    }

    static Policy getNextflowTimeoutPolicy(TaskRun task) {
        if (task.config.getTime()) {
            return new Policy().setTimeout(new Timeout(execute: task.config.getTime.toSeconds().toString + "s" )) // Convert to seconds
        }
    }
}
