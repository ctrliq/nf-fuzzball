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
        job.image = getTaskContainer(task) as java.net.URI
        job.resource = getComputeResources(task)
        job.command = getCommand(task)
        job.cwd = getTaskCwd(task)
        job.policy = getTimeoutPolicy(task)
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

    static String getTaskContainer(TaskRun task) {
        if (task.config.getContainer()) {
            return "docker://" + task.config.getContainer().toString()
        } else {
            throw new IllegalArgumentException("A container must be specified for the task.")
        }
    }

    static WorkflowDefinitionJobResource getComputeResources(TaskRun task) {
        WorkflowDefinitionJobResource resources = new WorkflowDefinitionJobResource()
        // getCpus always returns an int and defaults to 1
        // Todo: thread, affinity, devices, exclusive
        resources.cpu = new WorkflowDefinitionJobResourceCpu(cores: task.config.getCpus() as Long)
        resources.memory = new WorkflowDefinitionJobResourceMemory(size: task.config.getMemory()?.toString() ?: "1GiB")
        return resources
    }

    static String getTaskCwd(TaskRun task) {
        return task.workDir?.toString() ?: ""
    }

    static List<String> getCommand(TaskRun task) {
        return task.config.getShell() + task.CMD_RUN // Command to run
    }

    static Policy getTimeoutPolicy(TaskRun task) {
        // Todo: retry
        if (task.config.getTime()) {
            return new Policy(timeout: new Timeout(execute: "${task.config.getTime().toMinutes().toString()}m"))
        }
        return null
    }
}
