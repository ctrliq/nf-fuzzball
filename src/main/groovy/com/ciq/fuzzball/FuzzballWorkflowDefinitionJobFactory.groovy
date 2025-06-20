package com.ciq.fuzzball


import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j

import com.ciq.fuzzball.model.Policy
import com.ciq.fuzzball.model.Timeout
import com.ciq.fuzzball.model.URI
import com.ciq.fuzzball.model.WorkflowDefinitionJob
import com.ciq.fuzzball.model.WorkflowDefinitionJobResource
import com.ciq.fuzzball.model.WorkflowDefinitionJobResourceCpu
import com.ciq.fuzzball.model.WorkflowDefinitionJobResourceMemory

import nextflow.processor.TaskRun
import nextflow.executor.BashWrapperBuilder

@CompileStatic
@Slf4j
class FuzzballWorkflowDefinitionJobFactory {

    static WorkflowDefinitionJob create (TaskRun task, FuzzballExecutor executor){
        WorkflowDefinitionJob job = new WorkflowDefinitionJob()
        // fuzzball jobs have some limits on the job name (RFC1034 subdomain which means [0-9a-z-] at most 63 characters)
        // so let us use the tash hash instead b/c nf-core names get long quickly. And at least the hash can be
        // used to find the corresponding work directory easily.
        job.name = toSaveJobName(task.hash.toString())
        job.image = new URI(uri: getTaskContainer(task))
        job.resource = getComputeResources(task)
        job.command = getCommand(task)
        job.cwd = getTaskCwd(task)
        job.mounts = executor.mounts
        job.policy = getTimeoutPolicy(task)
        return job
    }

    static String toSaveJobName(String input) {
        if (!input) return 'a' // must start with a letter or digit
        String key = input
            .toLowerCase()
            .replaceAll(/[^a-z0-9-]/, '-') // Only allow a-z, 0-9, and hyphen
            .replaceAll(/-+/, '-')         // Collapse multiple hyphens
            .replaceAll(/^-+/, '')         // Remove leading hyphens
            .replaceAll(/-+$/, '')         // Remove trailing hyphens
        if (key.length() > 63) key = key.substring(0, 63)
        return key
    }

    static String getTaskContainer(TaskRun task) {
        if (task.getContainer()) {
            return 'docker://' + task.getContainer().toString()
        } else {
            throw new IllegalArgumentException('A container must be specified for the task.')
        }
    }

    static WorkflowDefinitionJobResource getComputeResources(TaskRun task) {
        WorkflowDefinitionJobResource resources = new WorkflowDefinitionJobResource()
        // getCpus always returns an int and defaults to 1
        // Todo: thread, affinity, devices, exclusive
        resources.cpu = new WorkflowDefinitionJobResourceCpu(cores: task.config.getCpus() as Long)
        resources.memory = new WorkflowDefinitionJobResourceMemory(size: task.config.getMemory()?.toString() ?: '1GiB')
        return resources
    }

    static String getTaskCwd(TaskRun task) {
        return task.workDir?.toString() ?: ''
    }

    static List<String> getCommand(TaskRun task) {
        List<String> command = BashWrapperBuilder.BASH as ArrayList<String>
        command << task.workDir.resolve(TaskRun.CMD_RUN).getName()
        return command
    }

    static Policy getTimeoutPolicy(TaskRun task) {
        // Todo: retry
        if (task.config.getTime()) {
            return new Policy(timeout: new Timeout(execute: "${task.config.getTime().toMinutes().toString()}m"))
        }
        return null
    }
}
