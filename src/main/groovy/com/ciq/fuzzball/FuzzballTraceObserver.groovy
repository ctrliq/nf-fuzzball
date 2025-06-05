package com.ciq.fuzzball

import java.nio.file.Path

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import nextflow.Session
import nextflow.processor.TaskHandler
import nextflow.processor.TaskProcessor
import nextflow.processor.TaskRun
import nextflow.trace.TraceObserver
import nextflow.trace.TraceRecord

//TODO: do we want to keep this?
/**
 * Implements an observer that allows implementing custom
 * logic on nextflow execution events.
 */
@Slf4j
@CompileStatic
class FuzzballTraceObserver implements TraceObserver {

    @Override
    void onFlowCreate(Session session) {
        println 'Pipeline is starting!'
    }

    @Override
    void onFlowComplete() {
        println 'Pipeline complete!'
    }

    @Override
    void onFlowBegin() {}

    @Override
    void onProcessCreate(TaskProcessor process) {
        println 'Process created!'
    }

    @Override
    void onProcessTerminate(TaskProcessor process) {}

    @Override
    void onProcessPending(TaskHandler handler, TraceRecord trace) {}

    @Override
    void onProcessSubmit(TaskHandler handler, TraceRecord trace) {
        println "Process submitted! Will use container ${handler.task.getContainer()}"
    }

    @Override
    void onProcessStart(TaskHandler handler, TraceRecord trace) {
        println 'Process started!'
    }

    @Override
    void onProcessComplete(TaskHandler handler, TraceRecord trace) {
        println 'Process completed!'
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
