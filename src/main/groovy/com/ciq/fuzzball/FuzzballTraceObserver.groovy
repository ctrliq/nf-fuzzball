package com.ciq.fuzzball


import com.ciq.fuzzball.model.WorkflowDefinition
import com.ciq.fuzzball.model.WorkflowDefinitionJob
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import nextflow.Session
import nextflow.processor.TaskHandler
import nextflow.processor.TaskProcessor
import nextflow.processor.TaskRun
import nextflow.trace.TraceObserver
import nextflow.trace.TraceRecord

import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.DumperOptions

import java.nio.file.Path

/**
 * Implements an observer that allows implementing custom
 * logic on nextflow execution events.
 */
@Slf4j
@CompileStatic
class FuzzballTraceObserver implements TraceObserver {

    @Override
    void onFlowCreate(Session session) {
        println "Pipeline is starting! 🚀"
    }

    @Override
    void onFlowComplete() {
        println "Pipeline complete! 👋"
    }

    @Override
    void onFlowBegin() {}

    @Override
    void onProcessCreate(TaskProcessor process) {
        println "Process created!"
    }

    @Override
    void onProcessTerminate(TaskProcessor process) {}

    @Override
    void onProcessPending(TaskHandler handler, TraceRecord trace) {}

    @Override
    void onProcessSubmit(TaskHandler handler, TraceRecord trace) {
        println "Process submitted!"
    }

    @Override
    void onProcessStart(TaskHandler handler, TraceRecord trace) {
        println "Process started!"
        TaskRun task = handler.getTask()

        // Generate a Fuzzball job using a task
        FuzzballWorkflowDefinitionJobFactory jobFactory = new FuzzballWorkflowDefinitionJobFactory()
        WorkflowDefinitionJob job = jobFactory.create(task)
        
        // Add the job into a WorkflowDefinition
        WorkflowDefinition wfDef = new WorkflowDefinition(
            version: "v1",
            jobs: [(job.getName()): job]
        )

        // Print the workflow definition in YAML format
        DumperOptions options = new DumperOptions()
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
        options.setPrettyFlow(true)
        Yaml yaml = new Yaml(options)
        String yamlStr = yaml.dump(wfDef)
        println "Workflow Definition YAML:\n${yamlStr}"
    }

    @Override
    void onProcessComplete(TaskHandler handler, TraceRecord trace) {
        println "Process completed!"
    }

    @Override
    void onProcessCached(TaskHandler handler, TraceRecord trace) {}

    @Override
    boolean enableMetrics() { false }

    @Override
    void onFlowError(TaskHandler handler, TraceRecord trace) {}

    @Override
    void onFilePublish(Path destination) {}

    @Override
    void onFilePublish(Path destination, Path source) {
        onFilePublish(destination)
    }

}