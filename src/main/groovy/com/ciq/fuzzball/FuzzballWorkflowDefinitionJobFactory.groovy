package com.ciq.fuzzball

import com.ciq.fuzzball.model.Policy
import com.ciq.fuzzball.model.Timeout
import com.ciq.fuzzball.model.WorkflowDefinitionJob
import com.ciq.fuzzball.model.WorkflowDefinitionJobResource
import com.ciq.fuzzball.model.WorkflowDefinitionJobResourceCpu
import com.ciq.fuzzball.model.WorkflowDefinitionJobResourceMemory
import nextflow.processor.TaskRun

class FuzzballWorkflowDefinitionJobFactory {

    static WorkflowDefinitionJob create (TaskRun task){
        WorkflowDefinitionJob job = new WorkflowDefinitionJob()
        job.setName(getNextflowTaskName(task))
        job.setImage(getNextflowTaskContainer(task) as java.net.URI)
        job.setResource(getNextflowComputeResources(task))
        job.setCommand(getNextflowCommand(task))
        job.setCwd(getNextflowTaskCwd(task))
        job.setPolicy(getNextflowTimeoutPolicy(task))
        return job
    }

    static String getNextflowTaskName(TaskRun task){
        if (task.getName()){
            return task.getName().replaceAll(/[\[\]\(\)\{\}]/, '')    // Remove all brackets
                                 .replaceAll(/\s+/, '-') // Replace whitespace with '-'
        } else {
            return "nf-task"
        }
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
